#pragma once
// QUIC client Initial decryption (RFC 9001 §5, RFC 9369 for v2) to recover
// the CRYPTO stream that carries the TLS ClientHello. Initial keys derive
// from the client's Destination Connection ID, which is on the wire, so a
// passive observer can read the hello (this is by design: Initial packets
// only have integrity, not confidentiality, against on-path observers).

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct QuicCryptoChunk {
    uint64_t    offset = 0;
    std::string data;
};

struct QuicClientInitial {
    uint32_t    version = 0;
    std::string dcid;                       // raw bytes
    std::vector<QuicCryptoChunk> crypto;    // CRYPTO frames, in packet order
};

// Decrypt every Initial packet in a client->server UDP datagram (coalesced
// packets are walked) and return their CRYPTO frames. nullopt if the datagram
// carries no Initial packet that decrypts.
std::optional<QuicClientInitial> quic_decrypt_client_initial(const uint8_t* dgram, size_t len);

// Exposed for tests (RFC 9001 Appendix A vectors).
struct QuicInitialKeys {
    uint8_t secret[32];
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];
};
bool quic_client_initial_keys(uint32_t version, const uint8_t* dcid, size_t dcid_len,
                              QuicInitialKeys& out);

inline bool quic_is_short_header(const uint8_t* d, size_t len) {
    return len >= 1 && (d[0] & 0xC0) == 0x40;     // header form 0, fixed bit 1
}
