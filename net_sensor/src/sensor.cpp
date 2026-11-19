#include "sensor.h"

#include "packet.h"

#include <netinet/in.h>

#include <algorithm>

namespace {
constexpr size_t kMaxDnsDedup = 100000;
}

Sensor::Sensor(const Indicators& ind, const SensorConfig& cfg, Output& out)
    : ind_(ind), cfg_(cfg), out_(out), tracker_(cfg, ind, dns_, out) {}

void Sensor::on_frame(const uint8_t* data, size_t caplen, int dlt, Ts ts) {
    ++frames_;
    if (auto p = parse_packet(data, caplen, dlt)) {
        ++parsed_;
        const bool udp = p->proto == IPPROTO_UDP;
        if (udp && (p->src.port == 53 || p->dst.port == 53)) {
            on_dns(*p, ts);
        } else if (cfg_.service_ports.test(p->src.port) || cfg_.service_ports.test(p->dst.port)) {
            if (udp) tracker_.on_quic(*p, ts);
            else     tracker_.on_tcp(*p, ts);
        }
    }
    advance(ts);
}

void Sensor::advance(Ts now) {
    if (now > now_) now_ = now;                  // timers never run backwards
    if (now_ < next_tick_) return;
    next_tick_ = now_ + kSec;
    tracker_.tick(now_);
    if (now_ >= next_housekeeping_) {
        next_housekeeping_ = now_ + 60 * kSec;
        dns_.expire(now_);
        for (auto it = dns_seen_.begin(); it != dns_seen_.end();)
            it = now_ - it->second > cfg_.dns_dedup_window ? dns_seen_.erase(it) : std::next(it);
    }
}

void Sensor::on_dns(const ParsedPacket& p, Ts ts) {
    auto msg = parse_dns(p.payload, p.cap_len);
    if (!msg) return;
    ++dns_msgs_;

    if (msg->response) {
        if (msg->rcode != 0) return;
        for (const auto& a : msg->answers)
            if (a.type == 1 || a.type == 28)
                dns_.learn(p.dst.ip, a.addr, msg->qname, a.ttl, ts);   // dst = the client that asked
        return;
    }

    const std::string* cat = ind_.category_of(msg->qname);
    if (!cat || ind_.sanctioned_name(msg->qname)) return;

    // One event per (client, name) per window: browsers re-query constantly.
    if (dns_seen_.size() >= kMaxDnsDedup) dns_seen_.clear();
    auto [it, inserted] = dns_seen_.try_emplace(DedupKey{p.src.ip, msg->qname}, ts);
    if (!inserted) {
        if (ts - it->second < cfg_.dns_dedup_window) return;
        it->second = ts;
    }
    ++dns_events_;
    Event e("dns", ts);
    const char* tn = dns_type_name(msg->qtype);
    e.str("client", p.src.ip.str())
        .str("resolver", p.dst.ip.str())
        .str("qname", msg->qname)
        .str("qtype", tn ? tn : std::to_string(msg->qtype))
        .str("category", *cat);
    out_.emit(e);
}

void Sensor::shutdown() {
    tracker_.shutdown(now_);
}

void Sensor::emit_stats(const CaptureStats& cs) {
    const auto& t = tracker_.stats();
    Event e("stats", now_);
    e.uinteger("frames", frames_)
        .uinteger("parsed", parsed_)
        .uinteger("dns_msgs", dns_msgs_)
        .uinteger("dns_events", dns_events_)
        .uinteger("flows_active", tracker_.active())
        .uinteger("flows_created", t.flows_created)
        .uinteger("flows_rejected", t.flows_rejected)
        .uinteger("hellos_tcp", t.hellos_tcp)
        .uinteger("hellos_quic", t.hellos_quic)
        .uinteger("hello_failures", t.hello_failures)
        .uinteger("quic_initials", t.quic_initials)
        .uinteger("conn_events", t.conn_events)
        .uinteger("stream_alerts", t.stream_alerts)
        .uinteger("upload_alerts", t.upload_alerts);
    if (cs.valid) {
        e.uinteger("pcap_received", cs.received)
            .uinteger("pcap_dropped", cs.dropped)
            .uinteger("pcap_if_dropped", cs.if_dropped);
    }
    out_.emit(e);
}
