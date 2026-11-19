#include "flow.h"

#include "quic.h"

#include <netinet/in.h>

#include <algorithm>
#include <cmath>
#include <cstring>

using namespace tcpflag;

namespace {

// "CONNECT host:port HTTP/1.1\r\n...\r\n\r\n" from a client to an explicit
// proxy. Returns the header length and the (escaped, lowercased) host.
bool parse_http_connect(const uint8_t* p, size_t n, size_t& header_len, std::string& host) {
    static const char kVerb[] = "CONNECT ";
    if (n < sizeof kVerb || std::memcmp(p, kVerb, sizeof kVerb - 1) != 0) return false;
    const std::string s(reinterpret_cast<const char*>(p), std::min<size_t>(n, 8192));
    const size_t end = s.find("\r\n\r\n");
    if (end == std::string::npos) return false;            // request split over segments: rare, skip
    const size_t a = sizeof kVerb - 1;
    const size_t sp = s.find(' ', a);
    if (sp == std::string::npos || sp > end) return false;
    std::string authority = s.substr(a, sp - a);
    if (!authority.empty() && authority.front() == '[') {   // [v6]:port
        authority = authority.substr(1, authority.find(']') - 1);
    } else if (const size_t colon = authority.rfind(':'); colon != std::string::npos) {
        authority.resize(colon);
    }
    if (authority.empty()) return false;
    host.clear();
    append_host_escaped(host, reinterpret_cast<const uint8_t*>(authority.data()), authority.size(),
                        /*allow_dot=*/true);
    header_len = end + 4;
    return true;
}

// Destination domain of a SOCKS5 (ATYP=domain) or SOCKS4a CONNECT request.
bool parse_socks_target(const uint8_t* p, size_t n, std::string& host) {
    const uint8_t* name = nullptr;
    size_t len = 0;
    if (n >= 7 && p[0] == 5 && p[1] == 1 && p[2] == 0 && p[3] == 3) {
        len = p[4];
        if (len == 0 || n < 5 + len + 2) return false;
        name = p + 5;
    } else if (n >= 10 && p[0] == 4 && p[1] == 1 && p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] != 0) {
        const uint8_t* user_end = static_cast<const uint8_t*>(std::memchr(p + 8, 0, n - 8));
        if (!user_end) return false;
        name = user_end + 1;
        const size_t rest = n - size_t(name - p);
        const uint8_t* name_end = static_cast<const uint8_t*>(std::memchr(name, 0, rest));
        if (!name_end || name_end == name) return false;
        len = size_t(name_end - name);
    } else {
        return false;
    }
    host.clear();
    append_host_escaped(host, name, std::min<size_t>(len, 255), /*allow_dot=*/true);
    return true;
}

}  // namespace

// =====================================================================
// StreamDetector
// =====================================================================

std::optional<BurstResult> StreamDetector::on_data(bool c2s, size_t len, Ts t) {
    std::optional<BurstResult> closed;
    if (open_ && t - last_pkt_ > cfg_->burst_gap) closed = close_burst();

    if (c2s) {
        if (open_) up_ += len;
        if (len >= cfg_->request_min) {
            if (last_request_ == kNever || t - last_request_ > cfg_->request_window)
                pending_request_bytes_ = 0;
            last_request_ = t;
            pending_request_bytes_ += len;
        }
        return closed;
    }

    if (!open_) {
        open_ = true;
        overlong_ = false;
        start_ = last_pkt_ = last_event_ = t;
        pkts_ = small_ = 0;
        events_ = 1;
        down_ = up_ = 0;
        gaps_ms_.clear();
        prompted_ = last_request_ != kNever && t - last_request_ <= cfg_->request_window;
        request_bytes_ = prompted_ ? pending_request_bytes_ : 0;
        pending_request_bytes_ = 0;
    } else if (t - last_event_ >= cfg_->coalesce) {
        // Segments of one write arrive back to back; count them as one event
        // so TCP segmentation doesn't distort the inter-arrival statistics.
        if (gaps_ms_.size() < kMaxGaps) gaps_ms_.push_back(float(t - last_event_) / 1000.f);
        ++events_;
        last_event_ = t;
    }
    ++pkts_;
    down_ += len;
    if (len <= cfg_->small_max) ++small_;
    last_pkt_ = t;
    if (t - start_ > cfg_->max_duration) overlong_ = true;
    return closed;
}

std::optional<BurstResult> StreamDetector::poll(Ts now, bool force) {
    if (open_ && (force || now - last_pkt_ > cfg_->burst_gap)) return close_burst();
    return std::nullopt;
}

BurstResult StreamDetector::close_burst() {
    open_ = false;
    BurstResult r;
    r.pkts          = pkts_;
    r.events        = events_;
    r.prompted      = prompted_;
    r.down_bytes    = down_;
    r.up_bytes      = up_;
    r.request_bytes = request_bytes_;
    const Ts dur    = last_pkt_ - start_;
    r.duration_s    = double(dur) / double(kSec);
    r.small_ratio   = pkts_ ? double(small_) / pkts_ : 0.0;

    if (!gaps_ms_.empty()) {
        std::vector<float> g = gaps_ms_;
        auto mid = g.begin() + std::ptrdiff_t(g.size() / 2);
        std::nth_element(g.begin(), mid, g.end());
        const double med = *mid;
        r.median_gap_ms = med;
        // Cadence: share of gaps within 3x of the median. Token streams are
        // steady; page loads and bulk transfers are bursty or back-to-back.
        size_t steady = 0;
        for (float x : gaps_ms_)
            if (x >= med / 3.0 && x <= med * 3.0) ++steady;
        r.cadence = double(steady) / double(gaps_ms_.size());
    }
    if (gaps_ms_.capacity() > 64) std::vector<float>().swap(gaps_ms_);
    else gaps_ms_.clear();

    const auto& c = *cfg_;
    const double med_us = r.median_gap_ms * 1000.0;
    if (overlong_)                                 r.reject = "too_long";
    else if (r.events < c.min_events)              r.reject = "few_events";
    else if (dur < c.min_duration)                 r.reject = "too_short";
    else if (med_us < double(c.min_median_gap))   r.reject = "too_fast";
    else if (med_us > double(c.max_median_gap))    r.reject = "too_slow";
    else if (r.small_ratio < c.min_small_ratio)    r.reject = "large_packets";
    else if (double(r.up_bytes) > c.max_up_down * double(r.down_bytes)) r.reject = "bidirectional";
    else r.qualifies = true;

    r.score = W_PROMPTED * (r.prompted ? 1.0 : 0.0) + W_SMALL * r.small_ratio +
              W_CADENCE * r.cadence + W_DURATION * std::min(1.0, r.duration_s / 3.0);
    return r;
}

// =====================================================================
// FlowTracker
// =====================================================================

struct FlowTracker::Flow {
    explicit Flow(const DetectorConfig& d) : detector(d) {}

    uint8_t  proto = 0;
    Endpoint client, server;
    Ts       first_seen = 0, last_seen = 0;
    bool     midstream = false;          // TCP flow picked up without its SYN/SYN-ACK
    bool     closed = false;             // FIN or RST seen
    const char* close_reason = "idle";

    // Client byte stream position (TCP).
    bool     saw_syn = false;
    uint32_t syn_seq = 0;
    bool     have_base = false;
    uint32_t data_base = 0;              // sequence number of the client's first payload byte

    // ClientHello.
    std::unique_ptr<HelloAssembler> hello_asm;
    bool        hello_done = false, hello_failed = false;
    uint32_t    hello_attempts = 0;
    std::string quic_dcid;
    std::string sni, ja4, alpn;
    bool        ech_ext = false;
    std::string connect_host;            // target named in an HTTP CONNECT / SOCKS request
    uint8_t     preamble_segments = 0;   // non-TLS client segments seen before the hello

    // Destination identity.
    bool        identity_done = false;
    std::string name;                    // what we call the destination
    const char* via = "ip";              // sni | connect | dns | dns_shared | ip
    std::string category;                // empty = not a listed AI service
    bool        sanctioned = false;
    bool        ech_outer = false;       // SNI was only an ECH public name

    // Application data.
    bool     app_phase = false;
    uint64_t up_pkts = 0, down_pkts = 0, up_bytes = 0, down_bytes = 0;
    StreamDetector detector;
    uint32_t ai_turns = 0;
    double   max_score = 0;
    bool     alert_emitted = false, upload_checked = false;
};

FlowTracker::FlowTracker(const SensorConfig& cfg, const Indicators& ind, const DnsCache& dns,
                         Output& out)
    : cfg_(cfg), ind_(ind), dns_(dns), out_(out) {}

FlowTracker::~FlowTracker() = default;

FlowTracker::Flow* FlowTracker::get_flow(const ParsedPacket& p, Ts ts) {
    const FlowKey key = FlowKey::make(p.src, p.dst, p.proto);
    const bool tcp = p.proto == IPPROTO_TCP;
    const bool syn_only = tcp && p.has(SYN) && !p.has(ACK);

    auto it = flows_.find(key);
    if (it != flows_.end()) {
        Flow& f = *it->second;
        // A new SYN on a finished connection, or one with a different ISN, is
        // a new connection reusing the 4-tuple. (Same ISN = SYN retransmit.)
        const bool reuse = syn_only && (f.closed || (f.saw_syn && p.seq != f.syn_seq) ||
                                        (!f.saw_syn && f.up_bytes + f.down_bytes > 0));
        if (!reuse) return &f;
        finish(f, ts, "reused");
        flows_.erase(it);
    }
    if (tcp && p.has(RST)) return nullptr;              // no state for stray resets
    if (flows_.size() >= cfg_.max_flows) {
        ++stats_.flows_rejected;
        return nullptr;
    }

    auto f = std::make_unique<Flow>(cfg_.det);
    f->proto = p.proto;
    f->first_seen = f->last_seen = ts;
    bool src_is_client;
    if (tcp && p.has(SYN)) {
        src_is_client = !p.has(ACK);                    // SYN: sender is client; SYN-ACK: receiver is
    } else {
        // No handshake seen: the service port identifies the server.
        f->midstream = tcp;
        const bool src_svc = cfg_.service_ports.test(p.src.port);
        const bool dst_svc = cfg_.service_ports.test(p.dst.port);
        src_is_client = (src_svc != dst_svc) ? dst_svc : p.src.port > p.dst.port;
    }
    f->client = src_is_client ? p.src : p.dst;
    f->server = src_is_client ? p.dst : p.src;
    ++stats_.flows_created;

    Flow* raw = f.get();
    flows_.emplace(key, std::move(f));
    return raw;
}

void FlowTracker::on_tcp(const ParsedPacket& p, Ts ts) {
    Flow* fp = get_flow(p, ts);
    if (!fp) return;
    Flow& f = *fp;
    ts = std::max(ts, f.last_seen);                     // out-of-order capture timestamps
    f.last_seen = ts;
    const bool c2s = p.src == f.client;

    if (p.has(SYN)) {
        if (!p.has(ACK) && c2s) {
            f.saw_syn = true;
            f.syn_seq = p.seq;
            f.have_base = true;
            f.data_base = p.seq + 1;
        } else if (p.has(ACK) && !c2s && !f.have_base) {
            f.have_base = true;
            f.data_base = p.ack;                        // SYN-ACK acknowledges client ISN+1
        }
    }
    if ((p.has(FIN) || p.has(RST)) && !f.closed) {
        f.closed = true;
        f.close_reason = p.has(RST) ? "rst" : "fin";
    }
    if (p.wire_len == 0) return;                        // pure ACK / control

    if (!f.hello_done && !f.hello_failed) {
        if (c2s) {
            feed_tcp_hello(f, p, ts);
        } else if (f.midstream && !f.hello_asm && f.connect_host.empty()) {
            give_up_hello(f, ts);                       // server talks first: we joined mid-connection
            f.app_phase = true;
        }
    }
    if (!f.app_phase && c2s && p.cap_len && tls_segment_has_app_data(p.payload, p.cap_len)) {
        f.app_phase = true;
        if (!f.hello_done && !f.hello_failed) give_up_hello(f, ts);
    }
    if (f.app_phase) account(f, c2s, p.wire_len, ts);
}

void FlowTracker::feed_tcp_hello(Flow& f, const ParsedPacket& p, Ts ts) {
    const uint8_t* data = p.payload;
    size_t len = p.cap_len;
    uint32_t seq = p.seq;
    if (len == 0) return;
    if (!f.hello_asm) {
        size_t hdr_len = 0;
        if (f.connect_host.empty() && parse_http_connect(data, len, hdr_len, f.connect_host)) {
            // Explicit proxy: the tunnelled ClientHello follows the CONNECT request.
            f.have_base = true;
            f.data_base = seq + uint32_t(hdr_len);
            if (hdr_len >= len) return;
            data += hdr_len;
            len -= hdr_len;
            seq += uint32_t(hdr_len);
        }
        const bool looks_tls = len >= 2 && data[0] == 0x16 && data[1] == 0x03;
        const bool known_start = f.have_base && !f.midstream;
        if (looks_tls) {
            if (!known_start || f.preamble_segments) {   // hello starts here
                f.have_base = true;
                f.data_base = seq;
            }
        } else if (known_start && !f.preamble_segments && seq != f.data_base) {
            // A later piece of the hello arrived before its first segment:
            // fall through and park it.
        } else if (known_start && f.preamble_segments < 4) {
            // Not TLS at stream start: possibly a proxy handshake (SOCKS)
            // before a tunnelled hello. Look at a few more segments.
            ++f.preamble_segments;
            if (f.connect_host.empty()) parse_socks_target(data, len, f.connect_host);
            return;
        } else {
            give_up_hello(f, ts);                       // not TLS, or joined mid-connection
            if (f.midstream) f.app_phase = true;
            return;
        }
        f.hello_asm = std::make_unique<HelloAssembler>(HelloAssembler::Mode::TlsRecords);
    }
    const uint32_t rel = seq - f.data_base;              // modulo-2^32, wraps correctly
    auto st = f.hello_asm->add(rel, data, len);
    if (st == HelloAssembler::Status::NeedMore && ++f.hello_attempts > 32)
        st = HelloAssembler::Status::Failed;
    if (st == HelloAssembler::Status::Done) {
        ++stats_.hellos_tcp;
        on_hello(f, f.hello_asm->hello(), 't', ts);
    } else if (st == HelloAssembler::Status::Failed) {
        give_up_hello(f, ts);
    }
}

void FlowTracker::on_quic(const ParsedPacket& p, Ts ts) {
    if (p.cap_len == 0) return;
    Flow* fp = get_flow(p, ts);
    if (!fp) return;
    Flow& f = *fp;
    ts = std::max(ts, f.last_seen);
    f.last_seen = ts;
    const bool c2s = p.src == f.client;

    if (p.payload[0] & 0x80) {                          // long header: handshake phase
        if (c2s && !f.hello_done && !f.hello_failed) feed_quic_initial(f, p, ts);
        return;
    }
    if (!quic_is_short_header(p.payload, p.cap_len)) return;
    if (!f.app_phase) {
        f.app_phase = true;
        if (!f.hello_done && !f.hello_failed) give_up_hello(f, ts);
    }
    account(f, c2s, p.wire_len, ts);
}

void FlowTracker::feed_quic_initial(Flow& f, const ParsedPacket& p, Ts ts) {
    if (++f.hello_attempts > 16) {
        give_up_hello(f, ts);
        return;
    }
    auto ini = quic_decrypt_client_initial(p.payload, p.cap_len);
    if (!ini) return;
    ++stats_.quic_initials;
    if (!f.hello_asm || ini->dcid != f.quic_dcid) {    // first Initial, or a new DCID after Retry
        f.quic_dcid = ini->dcid;
        f.hello_asm = std::make_unique<HelloAssembler>(HelloAssembler::Mode::Handshake);
    }
    auto st = HelloAssembler::Status::NeedMore;
    for (const auto& c : ini->crypto)
        st = f.hello_asm->add(c.offset, reinterpret_cast<const uint8_t*>(c.data.data()), c.data.size());
    if (st == HelloAssembler::Status::Done) {
        ++stats_.hellos_quic;
        on_hello(f, f.hello_asm->hello(), 'q', ts);
    } else if (st == HelloAssembler::Status::Failed) {
        give_up_hello(f, ts);
    }
}

void FlowTracker::on_hello(Flow& f, const TlsClientHello& ch, char transport, Ts ts) {
    f.hello_done = true;
    f.sni = ch.sni;
    f.ja4 = compute_ja4(ch, transport);
    f.alpn = printable(ch.alpn);
    f.ech_ext = ch.has_ech_ext;
    f.hello_asm.reset();
    if (cfg_.verbose) {
        Event e("hello", ts);
        e.str("transport", transport == 'q' ? "quic" : "tcp")
            .str("client", f.client.str())
            .str("server", f.server.str())
            .str("sni", f.sni.empty() ? "-" : f.sni)
            .str("ja4", f.ja4)
            .str("alpn", f.alpn.empty() ? "-" : f.alpn)
            .boolean("ech_ext", f.ech_ext);
        out_.emit(e);
    }
    resolve_identity(f, ts);
}

void FlowTracker::give_up_hello(Flow& f, Ts ts) {
    if (f.hello_asm) ++stats_.hello_failures;
    f.hello_failed = true;
    f.hello_asm.reset();
    resolve_identity(f, ts);
}

void FlowTracker::resolve_identity(Flow& f, Ts ts) {
    if (f.identity_done) return;
    f.identity_done = true;

    f.ech_outer = !f.sni.empty() && ind_.is_ech_outer(f.sni);
    if (!f.sni.empty() && !f.ech_outer) {
        f.name = f.sni;
        f.via = "sni";
    } else if (!f.connect_host.empty()) {
        f.name = f.connect_host;
        f.via = "connect";
    } else {
        bool shared = false;
        if (const std::string* n = dns_.lookup(f.client.ip, f.server.ip, ts, &shared)) {
            f.name = *n;
            f.via = shared ? "dns_shared" : "dns";
        }
    }
    if (!f.name.empty())
        if (const std::string* c = ind_.category_of(f.name)) f.category = *c;
    f.sanctioned = (!f.name.empty() && ind_.sanctioned_name(f.name)) || ind_.sanctioned_ip(f.server.ip);

    if (!f.category.empty() && !f.sanctioned) {
        ++stats_.conn_events;
        Event e("conn", ts);
        add_flow_fields(e, f);
        if (!f.sni.empty() && f.sni != f.name) e.str("sni", f.sni);
        if (!f.ja4.empty()) e.str("ja4", f.ja4);
        if (!f.alpn.empty()) e.str("alpn", f.alpn);
        out_.emit(e);
    }
}

void FlowTracker::add_flow_fields(Event& e, const Flow& f) const {
    e.str("transport", f.proto == IPPROTO_TCP ? "tcp" : "quic")
        .str("client", f.client.str())
        .str("server", f.server.str())
        .str("name", f.name.empty() ? f.server.ip.str() : f.name)
        .str("via", f.via)
        .str("category", f.category.empty() ? "unclassified" : f.category);
    if (f.ech_outer) e.boolean("ech", true);
}

void FlowTracker::account(Flow& f, bool c2s, size_t len, Ts ts) {
    if (c2s) { ++f.up_pkts; f.up_bytes += len; }
    else     { ++f.down_pkts; f.down_bytes += len; }

    if (auto r = f.detector.on_data(c2s, len, ts)) handle_burst(f, *r, ts);

    // DLP: a lot of data pushed to a known AI service in one connection
    // (pasted documents, file uploads).
    if (c2s && cfg_.upload_alert_bytes && !f.upload_checked && f.up_bytes >= cfg_.upload_alert_bytes) {
        f.upload_checked = true;
        resolve_identity(f, ts);
        if (!f.category.empty() && !f.sanctioned) {
            ++stats_.upload_alerts;
            Event e("alert", ts);
            e.str("kind", "ai_upload").str("severity", "high");
            add_flow_fields(e, f);
            e.uinteger("up_bytes", f.up_bytes).num("duration_s", double(ts - f.first_seen) / kSec, 1);
            if (!f.ja4.empty()) e.str("ja4", f.ja4);
            out_.emit(e);
        }
    }
}

void FlowTracker::handle_burst(Flow& f, const BurstResult& r, Ts ts) {
    if (cfg_.verbose && r.events >= 4) {
        Event e("burst", ts);
        e.str("client", f.client.str())
            .str("server", f.server.str())
            .num("score", r.score)
            .str("verdict", r.qualifies ? "qualifies" : r.reject)
            .boolean("prompted", r.prompted)
            .uinteger("pkts", r.pkts)
            .uinteger("events", r.events)
            .num("duration_s", r.duration_s, 2)
            .num("small_ratio", r.small_ratio, 2)
            .num("cadence", r.cadence, 2)
            .num("median_gap_ms", r.median_gap_ms, 1)
            .uinteger("down_bytes", r.down_bytes)
            .uinteger("up_bytes", r.up_bytes);
        out_.emit(e);
    }
    if (!r.qualifies || r.score < cfg_.det.threshold) return;
    ++f.ai_turns;
    f.max_score = std::max(f.max_score, r.score);
    if (f.alert_emitted) return;

    resolve_identity(f, ts);
    if (f.sanctioned) return;
    const bool known = !f.category.empty();
    // Unlisted destinations need the full prompt -> reply pattern.
    if (!known && !r.prompted) return;

    f.alert_emitted = true;
    ++stats_.stream_alerts;
    Event e("alert", ts);
    e.str("kind", "ai_stream").str("severity", known ? "high" : "medium");
    add_flow_fields(e, f);
    e.num("score", r.score)
        .boolean("prompted", r.prompted)
        .uinteger("request_bytes", r.request_bytes)
        .uinteger("reply_bytes", r.down_bytes)
        .uinteger("reply_pkts", r.pkts)
        .num("reply_s", r.duration_s, 2)
        .num("small_ratio", r.small_ratio, 2)
        .num("cadence", r.cadence, 2)
        .num("median_gap_ms", r.median_gap_ms, 1);
    if (!f.ja4.empty()) e.str("ja4", f.ja4);
    out_.emit(e);
}

void FlowTracker::finish(Flow& f, Ts ts, const char* reason) {
    if (auto r = f.detector.poll(ts, /*force=*/true)) handle_burst(f, *r, ts);
    if (!f.identity_done && (f.app_phase || cfg_.verbose)) resolve_identity(f, ts);

    const bool ai = !f.category.empty() && !f.sanctioned;
    const bool has_data = f.up_bytes + f.down_bytes > 0;
    if (!(f.alert_emitted || (ai && (has_data || f.hello_done)) || (cfg_.verbose && has_data))) return;

    Event e("flow_end", ts);
    add_flow_fields(e, f);
    e.str("reason", reason)
        .num("duration_s", double(f.last_seen - f.first_seen) / kSec, 1)
        .uinteger("up_bytes", f.up_bytes)
        .uinteger("down_bytes", f.down_bytes)
        .uinteger("up_pkts", f.up_pkts)
        .uinteger("down_pkts", f.down_pkts)
        .uinteger("ai_turns", f.ai_turns)
        .num("max_score", f.max_score);
    if (!f.ja4.empty()) e.str("ja4", f.ja4);
    out_.emit(e);
}

void FlowTracker::tick(Ts now) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        Flow& f = *it->second;
        if (auto r = f.detector.poll(now, false)) handle_burst(f, *r, now);
        Ts timeout;
        if (f.closed)                       timeout = cfg_.closed_linger;
        else if (f.proto != IPPROTO_TCP)    timeout = cfg_.udp_idle_timeout;
        else if (f.up_bytes + f.down_bytes || f.hello_done) timeout = cfg_.tcp_idle_timeout;
        else                                timeout = cfg_.tcp_embryonic;
        if (now - f.last_seen > timeout) {
            finish(f, now, f.closed ? f.close_reason : "idle");
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

void FlowTracker::shutdown(Ts now) {
    for (auto& kv : flows_) {
        Flow& f = *kv.second;
        finish(f, now, f.closed ? f.close_reason : "shutdown");
    }
    flows_.clear();
}
