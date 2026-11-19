#pragma once
// L2/L3/L4 decoding of captured frames.

#include "common.h"

#include <optional>

namespace tcpflag {
constexpr uint8_t FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;
}

struct ParsedPacket {
    Endpoint src, dst;
    uint8_t  proto     = 0;        // IPPROTO_TCP / IPPROTO_UDP
    uint8_t  tcp_flags = 0;
    uint32_t seq = 0, ack = 0;

    const uint8_t* payload = nullptr;
    size_t cap_len  = 0;           // payload bytes present in the capture buffer
    size_t wire_len = 0;           // payload bytes on the wire (from IP/UDP lengths);
                                   // excludes Ethernet padding, includes bytes cut by snaplen

    bool has(uint8_t flag) const { return (tcp_flags & flag) != 0; }
};

// Link types parse_packet understands: Ethernet (with 802.1Q/802.1ad tags),
// Linux cooked v1/v2 ("-i any"), raw IP, BSD loopback.
bool link_type_supported(int dlt);

// Returns nullopt for anything that isn't TCP/UDP over IPv4/IPv6, for
// truncated or inconsistent headers, and for non-first IP fragments.
std::optional<ParsedPacket> parse_packet(const uint8_t* data, size_t caplen, int dlt);
