#include "quic.h"

#include "common.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstring>
#include <memory>

namespace {

struct VersionInfo {
    uint32_t    version;
    uint8_t     salt[20];
    const char* key_label;
    const char* iv_label;
    const char* hp_label;
    unsigned    initial_type;     // long-header packet type bits for Initial
    unsigned    retry_type;
};

const VersionInfo kVersions[] = {
    {0x00000001,   // QUIC v1, RFC 9001 §5.2
     {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
      0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
     "quic key", "quic iv", "quic hp", 0, 3},
    {0x6b3343cf,   // QUIC v2, RFC 9369 §3.3.1
     {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
      0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
     "quicv2 key", "quicv2 iv", "quicv2 hp", 1, 0},
    {0xff00001d,   // draft-29, still seen from older stacks
     {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
      0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
     "quic key", "quic iv", "quic hp", 0, 3},
};

const VersionInfo* find_version(uint32_t v) {
    for (const auto& vi : kVersions)
        if (vi.version == v) return &vi;
    return nullptr;
}

bool hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* data, size_t dlen,
                 uint8_t out[32]) {
    unsigned int olen = 0;
    return HMAC(EVP_sha256(), key, int(klen), data, dlen, out, &olen) != nullptr && olen == 32;
}

// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context; out_len <= 32 so a
// single HKDF-Expand block suffices.
bool hkdf_expand_label(const uint8_t secret[32], const char* label, uint8_t* out, size_t out_len) {
    const size_t llen = std::strlen(label);
    uint8_t info[2 + 1 + 6 + 64 + 1 + 1];
    if (out_len > 32 || llen > 64) return false;
    size_t n = 0;
    info[n++] = uint8_t(out_len >> 8);
    info[n++] = uint8_t(out_len);
    info[n++] = uint8_t(6 + llen);
    std::memcpy(info + n, "tls13 ", 6);
    n += 6;
    std::memcpy(info + n, label, llen);
    n += llen;
    info[n++] = 0;      // context length
    info[n++] = 1;      // HKDF-Expand block counter
    uint8_t t[32];
    if (!hmac_sha256(secret, 32, info, n, t)) return false;
    std::memcpy(out, t, out_len);
    return true;
}

struct CtxFree { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CtxFree>;

bool aes128_ecb_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    CipherCtx c(EVP_CIPHER_CTX_new());
    int l = 0;
    return c && EVP_EncryptInit_ex(c.get(), EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 &&
           EVP_CIPHER_CTX_set_padding(c.get(), 0) == 1 &&
           EVP_EncryptUpdate(c.get(), out, &l, in, 16) == 1 && l == 16;
}

bool aes128_gcm_open(const uint8_t key[16], const uint8_t nonce[12], const uint8_t* aad,
                     size_t aad_len, const uint8_t* ct, size_t ct_len, const uint8_t tag[16],
                     uint8_t* out) {
    CipherCtx c(EVP_CIPHER_CTX_new());
    int l = 0, l2 = 0;
    if (!c || EVP_DecryptInit_ex(c.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(c.get(), nullptr, nullptr, key, nonce) != 1 ||
        EVP_DecryptUpdate(c.get(), nullptr, &l, aad, int(aad_len)) != 1 ||
        EVP_DecryptUpdate(c.get(), out, &l, ct, int(ct_len)) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1)
        return false;
    return EVP_DecryptFinal_ex(c.get(), out + l, &l2) == 1;
}

bool derive(const VersionInfo& vi, const uint8_t* dcid, size_t dcid_len, QuicInitialKeys& k) {
    uint8_t initial_secret[32];
    if (!hmac_sha256(vi.salt, sizeof vi.salt, dcid, dcid_len, initial_secret)) return false;  // HKDF-Extract
    return hkdf_expand_label(initial_secret, "client in", k.secret, 32) &&
           hkdf_expand_label(k.secret, vi.key_label, k.key, 16) &&
           hkdf_expand_label(k.secret, vi.iv_label, k.iv, 12) &&
           hkdf_expand_label(k.secret, vi.hp_label, k.hp, 16);
}

// Walk the frames of a decrypted Initial payload, collecting CRYPTO data.
// Chrome deliberately scatters CRYPTO, PING and PADDING frames ("chaos
// protection"), so order and fragmentation must not be assumed.
void collect_crypto(const uint8_t* p, size_t n, std::vector<QuicCryptoChunk>& out) {
    ByteReader r(p, n);
    while (!r.empty()) {
        uint64_t type;
        if (!r.varint(type)) return;
        switch (type) {
        case 0x00:                     // PADDING
        case 0x01:                     // PING
            break;
        case 0x02:
        case 0x03: {                   // ACK (+ECN)
            uint64_t largest, delay, count, first, gap, rlen;
            if (!r.varint(largest) || !r.varint(delay) || !r.varint(count) || !r.varint(first))
                return;
            if (count > 256) return;
            for (uint64_t i = 0; i < count; ++i)
                if (!r.varint(gap) || !r.varint(rlen)) return;
            if (type == 0x03) {
                uint64_t e;
                if (!r.varint(e) || !r.varint(e) || !r.varint(e)) return;
            }
            break;
        }
        case 0x06: {                   // CRYPTO
            uint64_t off, len;
            ByteReader data;
            if (!r.varint(off) || !r.varint(len) || !r.sub(size_t(len), data)) return;
            QuicCryptoChunk c;
            c.offset = off;
            c.data.assign(reinterpret_cast<const char*>(data.ptr()), data.left());
            out.push_back(std::move(c));
            break;
        }
        case 0x1c: {                   // CONNECTION_CLOSE
            uint64_t code, ftype, rlen;
            if (!r.varint(code) || !r.varint(ftype) || !r.varint(rlen) || !r.skip(size_t(rlen)))
                return;
            break;
        }
        default:
            return;                    // not allowed in Initial packets
        }
    }
}

bool decrypt_initial(const uint8_t* pk, size_t pn_off, size_t pkt_len, const QuicInitialKeys& k,
                     std::vector<QuicCryptoChunk>& out) {
    // Header protection sample starts 4 bytes after the packet number offset.
    if (pn_off + 4 + 16 > pkt_len) return false;
    uint8_t mask[16];
    if (!aes128_ecb_block(k.hp, pk + pn_off + 4, mask)) return false;

    const uint8_t first = pk[0] ^ (mask[0] & 0x0f);
    const size_t pn_len = (first & 0x03u) + 1u;
    if (pn_off + pn_len + 16 > pkt_len) return false;

    std::vector<uint8_t> hdr(pk, pk + pn_off + pn_len);
    hdr[0] = first;
    uint64_t pn = 0;
    for (size_t i = 0; i < pn_len; ++i) {
        hdr[pn_off + i] ^= mask[1 + i];
        pn = (pn << 8) | hdr[pn_off + i];
    }

    uint8_t nonce[12];
    std::memcpy(nonce, k.iv, 12);
    for (int i = 0; i < 8; ++i) nonce[11 - i] ^= uint8_t(pn >> (8 * i));

    const uint8_t* ct = pk + pn_off + pn_len;
    const size_t ct_len = pkt_len - pn_off - pn_len - 16;
    std::vector<uint8_t> plain(ct_len ? ct_len : 1);
    if (!aes128_gcm_open(k.key, nonce, hdr.data(), hdr.size(), ct, ct_len, ct + ct_len,
                         plain.data()))
        return false;
    collect_crypto(plain.data(), ct_len, out);
    return true;
}

}  // namespace

bool quic_client_initial_keys(uint32_t version, const uint8_t* dcid, size_t dcid_len,
                              QuicInitialKeys& out) {
    const VersionInfo* vi = find_version(version);
    return vi && derive(*vi, dcid, dcid_len, out);
}

std::optional<QuicClientInitial> quic_decrypt_client_initial(const uint8_t* d, size_t len) {
    QuicClientInitial res;
    bool any = false;
    bool have_keys = false;
    QuicInitialKeys keys{};

    size_t pos = 0;
    while (pos < len) {
        const uint8_t* pk = d + pos;
        const size_t rem = len - pos;
        if (rem < 7 || !(pk[0] & 0x80)) break;           // short header / padding: nothing coalesced after
        ByteReader r(pk, rem);
        uint8_t b0, dcid_len, scid_len;
        uint32_t version;
        ByteReader dcid;
        if (!r.u8(b0) || !r.u32(version)) break;
        const VersionInfo* vi = find_version(version);
        if (!vi) break;                                   // version negotiation / unknown version
        if (!r.u8(dcid_len) || dcid_len > 20 || !r.sub(dcid_len, dcid)) break;
        if (!r.u8(scid_len) || scid_len > 20 || !r.skip(scid_len)) break;

        const unsigned type = (b0 >> 4) & 0x03u;
        if (type == vi->retry_type) break;
        if (type == vi->initial_type) {
            uint64_t token_len;
            if (!r.varint(token_len) || !r.skip(size_t(token_len))) break;
        }
        uint64_t length;
        if (!r.varint(length) || length > r.left()) break;
        const size_t pn_off = size_t(r.ptr() - pk);
        const size_t pkt_len = pn_off + size_t(length);

        if (type == vi->initial_type) {
            const std::string id(reinterpret_cast<const char*>(dcid.ptr()), dcid.left());
            if (!have_keys || id != res.dcid || version != res.version) {
                if (!derive(*vi, dcid.ptr(), dcid.left(), keys)) break;
                have_keys = true;
                res.version = version;
                res.dcid = id;
            }
            if (decrypt_initial(pk, pn_off, pkt_len, keys, res.crypto)) any = true;
        }
        pos += pkt_len;
    }
    if (!any) return std::nullopt;
    return res;
}
