#include "tls.h"

#include "common.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cstdio>

namespace {

constexpr uint16_t kExtSni = 0x0000, kExtSigAlgs = 0x000d, kExtAlpn = 0x0010;
constexpr uint16_t kExtSupportedVersions = 0x002b, kExtEch = 0xfe0d;

constexpr char kHex[] = "0123456789abcdef";

void parse_sni(ByteReader ext, TlsClientHello& ch) {
    ByteReader list;
    if (!ext.sub16(list)) return;
    while (!list.empty()) {
        uint8_t type;
        ByteReader name;
        if (!list.u8(type) || !list.sub16(name)) return;
        if (type == 0) {                                  // host_name
            ch.sni.clear();
            append_host_escaped(ch.sni, name.ptr(), name.left(), /*allow_dot=*/true);
            while (!ch.sni.empty() && ch.sni.back() == '.') ch.sni.pop_back();
            return;
        }
    }
}

void parse_alpn(ByteReader ext, TlsClientHello& ch) {
    ByteReader list, proto;
    if (ext.sub16(list) && list.sub8(proto))
        ch.alpn.assign(reinterpret_cast<const char*>(proto.ptr()), proto.left());
}

const char* version_code(uint16_t v) {
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    case 0x0002: return "s2";
    case 0xfeff: return "d1";
    case 0xfefd: return "d2";
    case 0xfefc: return "d3";
    default:     return "00";
    }
}

bool is_alnum(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

// First/last character of the first ALPN value. Per the spec, if either end
// isn't ASCII alphanumeric, use the first hex digit of the first byte and the
// last hex digit of the last byte instead.
std::string alpn_code(const std::string& alpn) {
    if (alpn.empty()) return "00";
    const auto f = uint8_t(alpn.front()), l = uint8_t(alpn.back());
    if (is_alnum(f) && is_alnum(l)) return {char(f), char(l)};
    return {kHex[f >> 4], kHex[l & 0x0f]};
}

std::string join_hex(const std::vector<uint16_t>& v) {
    std::string s;
    s.reserve(v.size() * 5);
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) s.push_back(',');
        const uint16_t x = v[i];
        s.push_back(kHex[(x >> 12) & 0xf]);
        s.push_back(kHex[(x >> 8) & 0xf]);
        s.push_back(kHex[(x >> 4) & 0xf]);
        s.push_back(kHex[x & 0xf]);
    }
    return s;
}

std::string sha256_12(const std::string& in) {
    if (in.empty()) return "000000000000";
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(in.data()), in.size(), d);
    std::string out(12, '0');
    for (int i = 0; i < 6; ++i) {
        out[size_t(2 * i)]     = kHex[d[i] >> 4];
        out[size_t(2 * i + 1)] = kHex[d[i] & 0xf];
    }
    return out;
}

std::vector<uint16_t> without_grease(const std::vector<uint16_t>& v) {
    std::vector<uint16_t> out;
    out.reserve(v.size());
    for (uint16_t x : v)
        if (!tls_is_grease(x)) out.push_back(x);
    return out;
}

}  // namespace

bool tls_is_grease(uint16_t v) {
    // 0x0a0a, 0x1a1a, ..., 0xfafa
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

std::optional<TlsClientHello> parse_client_hello(const uint8_t* msg, size_t len) {
    ByteReader r(msg, len), body;
    uint8_t type;
    uint32_t blen;
    if (!r.u8(type) || type != 0x01 || !r.u24(blen) || !r.sub(blen, body)) return std::nullopt;

    TlsClientHello ch;
    ByteReader session_id, ciphers, compression, exts;
    if (!body.u16(ch.legacy_version) || !body.skip(32)) return std::nullopt;   // random
    if (!body.sub8(session_id) || session_id.left() > 32) return std::nullopt;
    if (!body.sub16(ciphers) || ciphers.left() % 2 != 0) return std::nullopt;
    while (!ciphers.empty()) {
        uint16_t c;
        ciphers.u16(c);
        ch.cipher_suites.push_back(c);
    }
    if (!body.sub8(compression)) return std::nullopt;
    if (body.empty()) return ch;                      // no extensions block at all
    if (!body.sub16(exts)) return std::nullopt;

    while (!exts.empty()) {
        uint16_t et;
        ByteReader ed;
        if (!exts.u16(et) || !exts.sub16(ed)) return std::nullopt;   // malformed block
        ch.extensions.push_back(et);
        switch (et) {
        case kExtSni:
            ch.has_sni_ext = true;
            parse_sni(ed, ch);
            break;
        case kExtAlpn:
            ch.has_alpn_ext = true;
            parse_alpn(ed, ch);
            break;
        case kExtSigAlgs: {
            ByteReader list;
            if (!ed.sub16(list)) break;
            uint16_t s;
            while (list.u16(s)) ch.sig_algs.push_back(s);
            break;
        }
        case kExtSupportedVersions: {
            ByteReader list;
            if (!ed.sub8(list)) break;               // length is checked against the extension
            uint16_t v, best = 0;
            while (list.u16(v))
                if (!tls_is_grease(v) && v > best) best = v;
            ch.supported_version = best;
            break;
        }
        case kExtEch:
            ch.has_ech_ext = true;
            break;
        default:
            break;
        }
    }
    return ch;
}

std::string compute_ja4(const TlsClientHello& ch, char transport) {
    const auto ciphers = without_grease(ch.cipher_suites);
    const auto exts    = without_grease(ch.extensions);
    const auto sigs    = without_grease(ch.sig_algs);

    const uint16_t ver = ch.supported_version ? ch.supported_version : ch.legacy_version;

    std::string a;
    a += transport;
    a += version_code(ver);
    a += ch.has_sni_ext ? 'd' : 'i';
    char counts[8];
    std::snprintf(counts, sizeof counts, "%02zu%02zu", std::min<size_t>(ciphers.size(), 99),
                  std::min<size_t>(exts.size(), 99));
    a += counts;
    a += alpn_code(ch.alpn);

    auto sorted_ciphers = ciphers;
    std::sort(sorted_ciphers.begin(), sorted_ciphers.end());
    const std::string b = sha256_12(join_hex(sorted_ciphers));

    // SNI and ALPN are already represented in part a; leave them out of c so
    // the same client hashes the same whatever it connects to.
    std::vector<uint16_t> sorted_exts;
    for (uint16_t e : exts)
        if (e != kExtSni && e != kExtAlpn) sorted_exts.push_back(e);
    std::sort(sorted_exts.begin(), sorted_exts.end());
    std::string c_in = join_hex(sorted_exts);
    if (!sigs.empty()) {
        c_in += '_';
        c_in += join_hex(sigs);                       // signature algorithms stay in wire order
    }
    const std::string c = sha256_12(c_in);

    return a + "_" + b + "_" + c;
}

bool tls_segment_has_app_data(const uint8_t* d, size_t len) {
    size_t pos = 0;
    while (pos + 5 <= len) {
        const uint8_t type = d[pos];
        if (type < 0x14 || type > 0x18 || d[pos + 1] != 0x03) return false;   // not at a record boundary
        if (type == 0x17) return true;
        pos += 5u + rd16(d + pos + 3);
    }
    return false;
}

std::string printable(const std::string& raw) {
    std::string out;
    for (unsigned char c : raw) {
        if (c >= 0x21 && c <= 0x7e && c != '\\' && c != '"') {
            out.push_back(char(c));
        } else {
            char buf[5];
            std::snprintf(buf, sizeof buf, "\\x%02x", c);
            out += buf;
        }
    }
    return out;
}

// ---------------- HelloAssembler ----------------

HelloAssembler::Status HelloAssembler::add(uint64_t offset, const uint8_t* data, size_t len) {
    if (status_ != Status::NeedMore || len == 0) return status_;
    if (offset >= kMaxBytes) return status_;
    if (offset + len > kMaxBytes) len = size_t(kMaxBytes - offset);

    const uint64_t have = stream_.size();
    const uint64_t end  = offset + len;
    if (end <= have) return status_;                  // retransmission / duplicate

    if (offset > have) {                              // beyond a gap: park it
        if (pending_.size() >= kMaxPending) return status_ = Status::Failed;
        std::string& slot = pending_[offset];
        if (slot.size() < len) slot.assign(reinterpret_cast<const char*>(data), len);
        return status_;
    }

    stream_.append(reinterpret_cast<const char*>(data + (have - offset)), size_t(end - have));
    // Pull in parked chunks that are now contiguous.
    while (!pending_.empty() && pending_.begin()->first <= stream_.size()) {
        const uint64_t off = pending_.begin()->first;
        const std::string& chunk = pending_.begin()->second;
        const uint64_t cend = off + chunk.size();
        if (cend > stream_.size()) stream_.append(chunk, size_t(stream_.size() - off), std::string::npos);
        pending_.erase(pending_.begin());
    }
    return status_ = evaluate();
}

HelloAssembler::Status HelloAssembler::evaluate() {
    const auto* s = reinterpret_cast<const uint8_t*>(stream_.data());
    const size_t n = stream_.size();

    std::string records;          // handshake bytes extracted from TLS records
    const uint8_t* hs = s;
    size_t hn = n;

    auto needed = [](const uint8_t* p, size_t k) -> size_t {
        return k >= 4 ? 4 + size_t(rd24(p + 1)) : SIZE_MAX;
    };

    if (mode_ == Mode::TlsRecords) {
        // Fail fast on streams that aren't TLS so we don't buffer them.
        if (n >= 1 && s[0] != 0x16) return Status::Failed;
        if (n >= 2 && s[1] != 0x03) return Status::Failed;
        size_t pos = 0;
        while (pos + 5 <= n) {
            const auto* rp = reinterpret_cast<const uint8_t*>(records.data());
            if (records.size() >= needed(rp, records.size())) break;
            if (s[pos] != 0x16 || s[pos + 1] != 0x03) return Status::Failed;
            const size_t rlen = rd16(s + pos + 3);
            if (rlen == 0 || rlen > 16384 + 2048) return Status::Failed;
            const size_t take = std::min(rlen, n - pos - 5);
            records.append(reinterpret_cast<const char*>(s + pos + 5), take);
            if (take < rlen) break;                       // record still arriving
            pos += 5 + rlen;
        }
        hs = reinterpret_cast<const uint8_t*>(records.data());
        hn = records.size();
    }

    if (hn >= 1 && hs[0] != 0x01) return Status::Failed;  // first message must be ClientHello
    if (hn < 4) return n >= kMaxBytes ? Status::Failed : Status::NeedMore;
    const size_t need = needed(hs, hn);
    if (need > kMaxBytes) return Status::Failed;
    if (hn < need) return n >= kMaxBytes ? Status::Failed : Status::NeedMore;

    hello_ = parse_client_hello(hs, need);
    stream_.clear();
    stream_.shrink_to_fit();
    pending_.clear();
    return hello_ ? Status::Done : Status::Failed;
}
