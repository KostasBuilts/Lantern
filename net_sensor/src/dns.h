#pragma once
// DNS message parsing (queries and responses) and an IP -> name cache built
// from observed answers. The cache names flows whose TLS SNI is missing or
// hidden by Encrypted Client Hello.

#include "common.h"

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

struct DnsAnswer {
    std::string name;
    uint16_t    type = 0;        // 1 = A, 28 = AAAA, 5 = CNAME
    uint32_t    ttl  = 0;
    IpAddr      addr;            // A / AAAA
    std::string target;          // CNAME
};

struct DnsMessage {
    uint16_t    id = 0;
    bool        response = false;
    uint8_t     rcode = 0;
    std::string qname;           // lowercased; odd bytes escaped as \DDD
    uint16_t    qtype = 0;
    std::vector<DnsAnswer> answers;   // A/AAAA/CNAME only, responses only
};

// Parse a DNS message from a UDP payload. Follows compression pointers with
// loop protection. Returns nullopt for anything malformed or not a standard
// query/response.
std::optional<DnsMessage> parse_dns(const uint8_t* data, size_t len);

const char* dns_type_name(uint16_t type);   // "A", "AAAA", ... or nullptr

class DnsCache {
public:
    // `client` resolved `name` to `addr`.
    void learn(const IpAddr& client, const IpAddr& addr, const std::string& name,
               uint32_t ttl, Ts now);

    // Name `client` last resolved to `server`. Falls back to any client's
    // resolution of that address (`*shared` = true): less reliable on shared
    // CDN addresses, but useful when the sensor only sees a forwarder's lookups.
    const std::string* lookup(const IpAddr& client, const IpAddr& server, Ts now,
                              bool* shared) const;

    void   expire(Ts now);
    size_t size() const { return by_pair_.size() + by_addr_.size(); }

private:
    struct Entry { std::string name; Ts expires; };
    struct PairKey {
        IpAddr client, addr;
        bool operator==(const PairKey& o) const { return client == o.client && addr == o.addr; }
    };
    struct PairHash {
        size_t operator()(const PairKey& k) const noexcept {
            return size_t(hash_ip(hash_ip(kFnvBasis, k.client), k.addr));
        }
    };

    static constexpr size_t kMaxEntries = 200000;
    std::unordered_map<PairKey, Entry, PairHash> by_pair_;
    std::unordered_map<IpAddr, Entry, IpAddrHash> by_addr_;
};
