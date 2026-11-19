#include "dns.h"

#include <algorithm>

namespace {

constexpr size_t kMaxName    = 255;
constexpr int    kMaxJumps   = 32;
constexpr size_t kMaxAnswers = 64;

// Decode a possibly-compressed name at `pos`. On success `pos` is advanced
// past the name as it appears at that position (pointer = 2 bytes).
bool read_name(const uint8_t* m, size_t len, size_t& pos, std::string& out) {
    out.clear();
    size_t p = pos;
    size_t wire = 0;
    bool jumped = false;
    int jumps = 0;
    for (;;) {
        if (p >= len) return false;
        const uint8_t l = m[p];
        if ((l & 0xC0) == 0xC0) {                        // compression pointer
            if (p + 1 >= len) return false;
            const size_t target = (size_t(l & 0x3F) << 8) | m[p + 1];
            if (target >= p || ++jumps > kMaxJumps) return false;   // backwards only, bounded
            if (!jumped) { pos = p + 2; jumped = true; }
            p = target;
            continue;
        }
        if (l & 0xC0) return false;                      // 0x40 / 0x80 label types
        if (l == 0) {
            if (!jumped) pos = p + 1;
            return true;
        }
        if (p + 1 + l > len) return false;
        wire += l + 1u;
        if (wire > kMaxName) return false;
        if (!out.empty()) out.push_back('.');
        append_host_escaped(out, m + p + 1, l, /*allow_dot=*/false);
        p += 1u + l;
    }
}

}  // namespace

const char* dns_type_name(uint16_t t) {
    switch (t) {
    case 1:   return "A";
    case 5:   return "CNAME";
    case 28:  return "AAAA";
    case 64:  return "SVCB";
    case 65:  return "HTTPS";
    default:  return nullptr;
    }
}

std::optional<DnsMessage> parse_dns(const uint8_t* m, size_t len) {
    if (len < 12) return std::nullopt;
    DnsMessage msg;
    msg.id = rd16(m);
    const uint16_t flags = rd16(m + 2);
    msg.response = (flags & 0x8000) != 0;
    if (((flags >> 11) & 0xF) != 0) return std::nullopt;   // opcode: standard query only
    msg.rcode = flags & 0xF;
    const uint16_t qd = rd16(m + 4), an = rd16(m + 6);
    if (qd == 0 || qd > 4) return std::nullopt;

    size_t pos = 12;
    std::string name;
    for (uint16_t i = 0; i < qd; ++i) {
        if (!read_name(m, len, pos, name) || pos + 4 > len) return std::nullopt;
        if (i == 0) {
            msg.qname = name;
            msg.qtype = rd16(m + pos);
        }
        pos += 4;
    }
    if (msg.qname.empty()) return std::nullopt;            // root / malformed
    if (!msg.response) return msg;

    // Answers: keep whatever parses; stop at the first malformed record.
    for (size_t i = 0; i < std::min<size_t>(an, kMaxAnswers); ++i) {
        DnsAnswer a;
        if (!read_name(m, len, pos, a.name) || pos + 10 > len) break;
        a.type = rd16(m + pos);
        const uint16_t cls = rd16(m + pos + 2);
        a.ttl = rd32(m + pos + 4);
        const size_t rdlen = rd16(m + pos + 8);
        pos += 10;
        if (pos + rdlen > len) break;
        const size_t rdata = pos;
        pos += rdlen;
        if (cls != 1) continue;                            // IN only
        if (a.type == 1 && rdlen == 4) {
            a.addr = IpAddr::from4(m + rdata);
        } else if (a.type == 28 && rdlen == 16) {
            a.addr = IpAddr::from6(m + rdata);
        } else if (a.type == 5) {
            size_t tp = rdata;
            if (!read_name(m, len, tp, a.target)) continue;
        } else {
            continue;
        }
        msg.answers.push_back(std::move(a));
    }
    return msg;
}

// ---------------- cache ----------------

void DnsCache::learn(const IpAddr& client, const IpAddr& addr, const std::string& name,
                     uint32_t ttl, Ts now) {
    // Clients and resolvers routinely keep using an address past its TTL, and
    // the flow may start well after the lookup, so keep entries for at least
    // 10 minutes (capped at 6 hours).
    const Ts keep = std::clamp<Ts>(Ts(ttl) * kSec, 600 * kSec, 6 * 3600 * kSec);
    if (size() >= kMaxEntries) {
        expire(now);
        if (size() >= kMaxEntries) { by_pair_.clear(); by_addr_.clear(); }   // hard bound
    }
    by_pair_[PairKey{client, addr}] = Entry{name, now + keep};
    by_addr_[addr] = Entry{name, now + keep};
}

const std::string* DnsCache::lookup(const IpAddr& client, const IpAddr& server, Ts now,
                                    bool* shared) const {
    auto it = by_pair_.find(PairKey{client, server});
    if (it != by_pair_.end() && it->second.expires >= now) {
        if (shared) *shared = false;
        return &it->second.name;
    }
    auto jt = by_addr_.find(server);
    if (jt != by_addr_.end() && jt->second.expires >= now) {
        if (shared) *shared = true;
        return &jt->second.name;
    }
    return nullptr;
}

void DnsCache::expire(Ts now) {
    for (auto it = by_pair_.begin(); it != by_pair_.end();)
        it = it->second.expires < now ? by_pair_.erase(it) : std::next(it);
    for (auto it = by_addr_.begin(); it != by_addr_.end();)
        it = it->second.expires < now ? by_addr_.erase(it) : std::next(it);
}
