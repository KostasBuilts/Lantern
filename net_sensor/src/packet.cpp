#include "packet.h"

#include <netinet/in.h>
#include <pcap/pcap.h>   // DLT_* constants only

#include <algorithm>

namespace {

constexpr uint16_t kEtIPv4 = 0x0800, kEtIPv6 = 0x86DD;
constexpr uint16_t kEtVlan = 0x8100, kEtQinQ = 0x88A8, kEtQinQOld = 0x9100;

struct L3 { size_t off; int ver; };

std::optional<L3> from_ethertype(uint16_t et, size_t off) {
    if (et == kEtIPv4) return L3{off, 4};
    if (et == kEtIPv6) return L3{off, 6};
    return std::nullopt;
}

std::optional<L3> from_version_nibble(const uint8_t* d, size_t len, size_t off) {
    if (len <= off) return std::nullopt;
    const int ver = d[off] >> 4;
    if (ver == 4 || ver == 6) return L3{off, ver};
    return std::nullopt;
}

std::optional<L3> find_l3(const uint8_t* d, size_t len, int dlt) {
    switch (dlt) {
    case DLT_EN10MB: {
        if (len < 14) return std::nullopt;
        uint16_t et = rd16(d + 12);
        size_t off = 14;
        // 802.1Q / 802.1ad (QinQ) tags: mirror ports frequently keep them.
        for (int tags = 0; et == kEtVlan || et == kEtQinQ || et == kEtQinQOld; ++tags) {
            if (tags >= 4 || len < off + 4) return std::nullopt;
            et = rd16(d + off + 2);
            off += 4;
        }
        return from_ethertype(et, off);
    }
    case DLT_LINUX_SLL:                       // 16-byte cooked header, protocol at 14
        if (len < 16) return std::nullopt;
        return from_ethertype(rd16(d + 14), 16);
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:                      // 20-byte cooked header, protocol at 0
        if (len < 20) return std::nullopt;
        return from_ethertype(rd16(d), 20);
#endif
    case DLT_NULL:
    case DLT_LOOP:                            // 4-byte address-family header
        return from_version_nibble(d, len, 4);
    case DLT_RAW:
#ifdef DLT_IPV4
    case DLT_IPV4:
#endif
#ifdef DLT_IPV6
    case DLT_IPV6:
#endif
        return from_version_nibble(d, len, 0);
    default:
        return std::nullopt;
    }
}

}  // namespace

bool link_type_supported(int dlt) {
    switch (dlt) {
    case DLT_EN10MB: case DLT_LINUX_SLL: case DLT_NULL: case DLT_LOOP: case DLT_RAW:
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
#endif
#ifdef DLT_IPV4
    case DLT_IPV4:
#endif
#ifdef DLT_IPV6
    case DLT_IPV6:
#endif
        return true;
    default:
        return false;
    }
}

std::optional<ParsedPacket> parse_packet(const uint8_t* d, size_t caplen, int dlt) {
    const auto l3 = find_l3(d, caplen, dlt);
    if (!l3) return std::nullopt;

    ParsedPacket p;
    size_t off = l3->off;
    size_t l4_off = 0;
    size_t l4_wire = 0;    // L4 header + payload length according to the IP header

    if (l3->ver == 4) {
        if (caplen < off + 20) return std::nullopt;
        const uint8_t* ip = d + off;
        if ((ip[0] >> 4) != 4) return std::nullopt;
        const size_t ihl = (ip[0] & 0x0fu) * 4u;
        if (ihl < 20 || caplen < off + ihl) return std::nullopt;
        size_t total = rd16(ip + 2);
        if (total == 0) total = caplen - off;          // TSO/GSO frames captured on the sender
        if (total < ihl) return std::nullopt;
        if (rd16(ip + 6) & 0x1fff) return std::nullopt; // non-first fragment: no L4 header
        p.proto  = ip[9];
        p.src.ip = IpAddr::from4(ip + 12);
        p.dst.ip = IpAddr::from4(ip + 16);
        l4_off  = off + ihl;
        l4_wire = total - ihl;
    } else {
        if (caplen < off + 40) return std::nullopt;
        const uint8_t* ip6 = d + off;
        if ((ip6[0] >> 4) != 6) return std::nullopt;
        size_t remaining = rd16(ip6 + 4);
        if (remaining == 0) remaining = caplen - off - 40;   // jumbogram / TSO
        uint8_t nh = ip6[6];
        p.src.ip = IpAddr::from6(ip6 + 8);
        p.dst.ip = IpAddr::from6(ip6 + 24);
        size_t pos = off + 40;
        // Walk extension headers (bounded).
        for (int i = 0; i < 8 && nh != IPPROTO_TCP && nh != IPPROTO_UDP; ++i) {
            size_t hl;
            if (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING || nh == IPPROTO_DSTOPTS) {
                if (caplen < pos + 2) return std::nullopt;
                hl = (d[pos + 1] + 1u) * 8u;
            } else if (nh == IPPROTO_FRAGMENT) {
                if (caplen < pos + 8) return std::nullopt;
                if (rd16(d + pos + 2) & 0xfff8) return std::nullopt;   // non-first fragment
                hl = 8;
            } else if (nh == IPPROTO_AH) {
                if (caplen < pos + 2) return std::nullopt;
                hl = (d[pos + 1] + 2u) * 4u;
            } else {
                return std::nullopt;              // ESP, no-next-header, unknown
            }
            if (caplen < pos + hl || remaining < hl) return std::nullopt;
            nh = d[pos];
            pos += hl;
            remaining -= hl;
        }
        if (nh != IPPROTO_TCP && nh != IPPROTO_UDP) return std::nullopt;
        p.proto = nh;
        l4_off  = pos;
        l4_wire = remaining;
    }

    // Bytes of L4 we may read: never past the IP datagram (Ethernet padding)
    // and never past the capture (snaplen).
    const size_t l4_cap = std::min(caplen - l4_off, l4_wire);
    const uint8_t* l4 = d + l4_off;

    if (p.proto == IPPROTO_TCP) {
        if (l4_cap < 20) return std::nullopt;
        const size_t thl = (l4[12] >> 4) * 4u;
        if (thl < 20 || l4_cap < thl) return std::nullopt;
        p.src.port  = rd16(l4);
        p.dst.port  = rd16(l4 + 2);
        p.seq       = rd32(l4 + 4);
        p.ack       = rd32(l4 + 8);
        p.tcp_flags = l4[13];
        p.payload   = l4 + thl;
        p.cap_len   = l4_cap - thl;
        p.wire_len  = l4_wire - thl;
    } else {
        if (l4_cap < 8) return std::nullopt;
        const size_t ulen = rd16(l4 + 4);
        if (ulen < 8 || ulen > l4_wire) return std::nullopt;   // also rejects fragmented datagrams
        p.src.port = rd16(l4);
        p.dst.port = rd16(l4 + 2);
        p.payload  = l4 + 8;
        p.cap_len  = std::min(l4_cap, ulen) - 8;
        p.wire_len = ulen - 8;
    }
    return p;
}
