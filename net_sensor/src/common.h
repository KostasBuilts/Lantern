#pragma once
// Shared primitives: packet time, addresses, flow keys, a bounds-checked byte
// reader and safe-for-logs string escaping.

#include <arpa/inet.h>
#include <sys/socket.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// ---------- time ----------
// All detection logic runs on *packet* timestamps (pcap header), never on the
// processing clock: libpcap delivers packets in batches, so wall-clock time at
// processing says nothing about packet spacing.
using Ts = int64_t;                  // microseconds since the Unix epoch
constexpr Ts kMs  = 1000;
constexpr Ts kSec = 1000 * kMs;

// ---------- big-endian loads (caller guarantees bounds) ----------
inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint32_t rd24(const uint8_t* p) {
    return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2];
}
inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

// ---------- addresses ----------
struct IpAddr {
    std::array<uint8_t, 16> b{};     // IPv4 uses the first 4 bytes, rest zero
    bool v6 = false;

    static IpAddr from4(const void* p) { IpAddr a; std::memcpy(a.b.data(), p, 4); return a; }
    static IpAddr from6(const void* p) { IpAddr a; a.v6 = true; std::memcpy(a.b.data(), p, 16); return a; }

    bool operator==(const IpAddr& o) const { return v6 == o.v6 && b == o.b; }
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    bool operator<(const IpAddr& o) const { return v6 != o.v6 ? v6 < o.v6 : b < o.b; }

    std::string str() const {
        char buf[INET6_ADDRSTRLEN] = {0};
        inet_ntop(v6 ? AF_INET6 : AF_INET, b.data(), buf, sizeof buf);
        return buf;
    }
};

struct Endpoint {
    IpAddr   ip;
    uint16_t port = 0;

    bool operator==(const Endpoint& o) const { return port == o.port && ip == o.ip; }
    bool operator!=(const Endpoint& o) const { return !(*this == o); }
    bool operator<(const Endpoint& o) const { return ip != o.ip ? ip < o.ip : port < o.port; }

    std::string str() const {
        return ip.v6 ? "[" + ip.str() + "]:" + std::to_string(port)
                     : ip.str() + ":" + std::to_string(port);
    }
};

inline uint64_t fnv1a(uint64_t h, const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}
constexpr uint64_t kFnvBasis = 1469598103934665603ULL;

inline uint64_t hash_ip(uint64_t h, const IpAddr& a) {
    h = fnv1a(h, a.b.data(), a.b.size());
    const uint8_t v = a.v6 ? 1 : 0;
    return fnv1a(h, &v, 1);
}

struct IpAddrHash {
    size_t operator()(const IpAddr& a) const noexcept { return size_t(hash_ip(kFnvBasis, a)); }
};

// Direction-independent flow key: endpoints are stored in sorted order. The
// key says nothing about which side is the client; flows track that
// separately (see flow.cpp).
struct FlowKey {
    Endpoint lo, hi;
    uint8_t  proto = 0;

    static FlowKey make(const Endpoint& a, const Endpoint& b, uint8_t proto) {
        FlowKey k;
        k.proto = proto;
        if (b < a) { k.lo = b; k.hi = a; } else { k.lo = a; k.hi = b; }
        return k;
    }
    bool operator==(const FlowKey& o) const { return proto == o.proto && lo == o.lo && hi == o.hi; }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        uint64_t h = hash_ip(kFnvBasis, k.lo.ip);
        h = hash_ip(h, k.hi.ip);
        const uint8_t tail[5] = {uint8_t(k.lo.port >> 8), uint8_t(k.lo.port),
                                 uint8_t(k.hi.port >> 8), uint8_t(k.hi.port), k.proto};
        return size_t(fnv1a(h, tail, sizeof tail));
    }
};

// ---------- bounds-checked reader ----------
// Every accessor fails (returns false) instead of reading past the end.
class ByteReader {
public:
    ByteReader() = default;
    ByteReader(const uint8_t* p, size_t n) : p_(p), end_(p + n) {}

    size_t left() const { return size_t(end_ - p_); }
    bool   empty() const { return p_ >= end_; }
    const uint8_t* ptr() const { return p_; }

    bool skip(size_t n) { if (left() < n) return false; p_ += n; return true; }
    bool u8(uint8_t& v)   { if (left() < 1) return false; v = p_[0]; p_ += 1; return true; }
    bool u16(uint16_t& v) { if (left() < 2) return false; v = rd16(p_); p_ += 2; return true; }
    bool u24(uint32_t& v) { if (left() < 3) return false; v = rd24(p_); p_ += 3; return true; }
    bool u32(uint32_t& v) { if (left() < 4) return false; v = rd32(p_); p_ += 4; return true; }

    // QUIC variable-length integer (RFC 9000 §16).
    bool varint(uint64_t& v) {
        if (left() < 1) return false;
        const size_t n = size_t(1) << (p_[0] >> 6);
        if (left() < n) return false;
        v = p_[0] & 0x3f;
        for (size_t i = 1; i < n; ++i) v = (v << 8) | p_[i];
        p_ += n;
        return true;
    }

    // Carve the next n bytes off as an independent reader.
    bool sub(size_t n, ByteReader& out) {
        if (left() < n) return false;
        out = ByteReader(p_, n);
        p_ += n;
        return true;
    }
    bool sub8(ByteReader& out)  { uint8_t n;  return u8(n)  && sub(n, out); }
    bool sub16(ByteReader& out) { uint16_t n; return u16(n) && sub(n, out); }

private:
    const uint8_t* p_   = nullptr;
    const uint8_t* end_ = nullptr;
};

// ---------- names from the wire ----------
// Append a hostname label/string taken from untrusted packet data. Letters are
// lowercased; [a-z0-9-_] (and '.' when allow_dot) pass through; anything else
// becomes \DDD (the dig convention). The result is plain printable ASCII, so
// it can't inject fake lines into logs, and a byte '.' smuggled inside a
// single DNS label can't masquerade as a label separator.
inline void append_host_escaped(std::string& out, const uint8_t* p, size_t n, bool allow_dot) {
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = p[i];
        if (c >= 'A' && c <= 'Z') c = uint8_t(c - 'A' + 'a');
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
                        c == '_' || (allow_dot && c == '.');
        if (ok) {
            out.push_back(char(c));
        } else {
            char buf[5];
            std::snprintf(buf, sizeof buf, "\\%03u", unsigned(c));
            out += buf;
        }
    }
}
