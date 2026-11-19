#pragma once
// TLS ClientHello parsing, JA4 fingerprinting, and reassembly of a
// ClientHello that spans several TCP segments / TLS records / QUIC CRYPTO
// frames.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

struct TlsClientHello {
    uint16_t legacy_version    = 0;
    uint16_t supported_version = 0;   // highest non-GREASE supported_versions entry, 0 if absent
    std::vector<uint16_t> cipher_suites;  // wire order, GREASE included
    std::vector<uint16_t> extensions;     // wire order, GREASE included
    std::vector<uint16_t> sig_algs;       // wire order, GREASE included

    bool        has_sni_ext = false;
    std::string sni;                  // first host_name, lowercased, odd bytes escaped
    bool        has_alpn_ext = false;
    std::string alpn;                 // first ALPN protocol, raw bytes
    bool        has_ech_ext = false;  // encrypted_client_hello (0xfe0d); may be GREASE ECH
};

bool tls_is_grease(uint16_t v);

// Parse a complete handshake message (starting at the 1-byte type field).
std::optional<TlsClientHello> parse_client_hello(const uint8_t* msg, size_t len);

// JA4 per the FoxIO specification. transport: 't' TLS/TCP, 'q' QUIC, 'd' DTLS.
std::string compute_ja4(const TlsClientHello& ch, char transport);

// True if a client->server TCP segment contains a TLS application_data record
// at a record boundary (i.e. the handshake is over from the client's side).
bool tls_segment_has_app_data(const uint8_t* data, size_t len);

// Printable rendering of arbitrary bytes for logs (non-printables as \xHH).
std::string printable(const std::string& raw);

// Accumulates the start of a byte stream (TCP payload from the client, or a
// QUIC CRYPTO stream) until a full ClientHello is available. Handles
// out-of-order and overlapping chunks, hellos split over several segments
// (post-quantum key shares push browser hellos past one MSS) and, in
// TlsRecords mode, hellos fragmented over several TLS records.
class HelloAssembler {
public:
    enum class Mode { TlsRecords, Handshake };
    enum class Status { NeedMore, Done, Failed };

    static constexpr size_t kMaxBytes   = 32 * 1024;
    static constexpr size_t kMaxPending = 64;

    explicit HelloAssembler(Mode m) : mode_(m) {}

    // offset is relative to the start of the stream.
    Status add(uint64_t offset, const uint8_t* data, size_t len);

    Status status() const { return status_; }
    const TlsClientHello& hello() const { return *hello_; }   // valid when Done

private:
    Status evaluate();

    Mode   mode_;
    Status status_ = Status::NeedMore;
    std::string stream_;                       // contiguous bytes from offset 0
    std::map<uint64_t, std::string> pending_;  // chunks beyond a gap
    std::optional<TlsClientHello> hello_;
};
