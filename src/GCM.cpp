#include "GCM.h"
#include <cstring>
#include <stdexcept>
#include <algorithm>

// Helper: XOR two 16-byte vectors
void AES256_GCM::XOR(std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    for (size_t i = 0; i < 16; ++i) a[i] ^= b[i];
}

AES256_GCM::AES256_GCM(const std::vector<uint8_t>& key)
    : aes(key)
{
    // compute H = AES_K(0^128)
    H.assign(16, 0);
    aes.EncryptBlock(H.data());
    PrecomputeHTable();
}

void AES256_GCM::PrecomputeHTable() {
    std::array<uint8_t, 16> v{};
    std::copy(H.begin(), H.end(), v.begin());
    for (int i = 0; i < 128; ++i) {
        Htable[i] = v;
        uint8_t lsb = v[15] & 1;
        for (int j = 15; j > 0; --j) {
            v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] = static_cast<uint8_t>(v[0] >> 1);
        if (lsb) v[0] ^= 0xe1;
    }
}

// increment rightmost 32 bits (bytes 12..15) as big-endian counter
void AES256_GCM::Inc32(std::vector<uint8_t>& counter) const {
    for (int i = 15; i >= 12; --i) {
        if (++counter[i]) break;
    }
}

// GCTR: AES-CTR using block encryption in-place (counter is 16 bytes).
// We follow convention: caller provides icb (J0). We encrypt counter+1, counter+2, ...
std::vector<uint8_t> AES256_GCM::GCTR(const std::vector<uint8_t>& icb,
                                      const std::vector<uint8_t>& input) const {
    if (icb.size() != 16) throw std::invalid_argument("icb must be 16 bytes");
    std::vector<uint8_t> output(input.size());
    std::vector<uint8_t> counter = icb;
    std::vector<uint8_t> block(16);

    size_t n = (input.size() + 15) / 16;
    for (size_t i = 0; i < n; ++i) {
        Inc32(counter); // increment before use -> first keystream block is J0+1
        std::memcpy(block.data(), counter.data(), 16);
        aes.EncryptBlock(block.data()); // block now keystream
        size_t offset = i * 16;
        size_t len = std::min<size_t>(16, input.size() - offset);
        for (size_t j = 0; j < len; ++j)
            output[offset + j] = input[offset + j] ^ block[j];
    }
    return output;
}

// Multiply X and Y in GF(2^128) (X and Y are 16-byte big-endian bitstrings)
// Implementation: bitwise algorithm (shift-and-xor) with reduction polynomial 0xe1
std::vector<uint8_t> AES256_GCM::GaloisMultiply(
    const std::vector<uint8_t>& X,
    const std::vector<uint8_t>& Y) const
{
    // Fast path: GHASH always multiplies by H, so reuse precomputed shifts
    if (Y == H) {
        std::array<uint8_t, 16> Z{};
        for (int i = 0; i < 128; ++i) {
            int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
            if (bit) {
                for (int j = 0; j < 16; ++j) Z[j] ^= Htable[i][j];
            }
        }
        return std::vector<uint8_t>(Z.begin(), Z.end());
    }

    // Fallback generic multiply
    std::vector<uint8_t> Z(16, 0);
    std::vector<uint8_t> V = Y; // copy
    for (int i = 0; i < 128; ++i) {
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
        if (bit) {
            for (int j = 0; j < 16; ++j) Z[j] ^= V[j];
        }
        uint8_t lsb = V[15] & 1;
        for (int j = 15; j > 0; --j) {
            V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        }
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    return Z;
}

// GHASH: process AAD then ciphertext, returning 16-byte tag S
std::vector<uint8_t> AES256_GCM::GHASH(
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext) const
{
    std::vector<uint8_t> X(16, 0);
    auto process = [&](const std::vector<uint8_t>& data) {
        for (size_t i = 0; i < data.size(); i += 16) {
            std::vector<uint8_t> block(16, 0);
            size_t len = std::min<size_t>(16, data.size() - i);
            std::memcpy(block.data(), data.data() + i, len);
            XOR(X, block);
            X = GaloisMultiply(X, H);
        }
    };
    if (!aad.empty()) process(aad);
    if (!ciphertext.empty()) process(ciphertext);

    // process lengths: 64-bit AAD length || 64-bit ciphertext length (both in bits) per spec
    std::vector<uint8_t> lenBlock(16, 0);
    uint64_t aadBits = (uint64_t)aad.size() * 8;
    uint64_t cBits = (uint64_t)ciphertext.size() * 8;
    // store as big-endian 64-bit || 64-bit
    for (int i = 0; i < 8; ++i) lenBlock[7 - i] = static_cast<uint8_t>(aadBits >> (i * 8));
    for (int i = 0; i < 8; ++i) lenBlock[15 - i] = static_cast<uint8_t>(cBits >> (i * 8));
    XOR(X, lenBlock);
    X = GaloisMultiply(X, H);

    return X;
}

// Encrypt: produce ciphertext and tag_out (16 bytes)
std::vector<uint8_t> AES256_GCM::Encrypt(
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad,
    std::vector<uint8_t>& tag_out)
{
    // J0 = IV || 0x00000001 for 96-bit IV (12 bytes)
    if (iv.size() != 12) {
        throw std::invalid_argument("Only 12-byte IV supported in this simple implementation");
    }
    std::vector<uint8_t> J0(16, 0);
    std::memcpy(J0.data(), iv.data(), 12);
    J0[15] = 1;

    // CTR encrypt (GCTR) -> ciphertext
    std::vector<uint8_t> ciphertext = GCTR(J0, plaintext);

    // GHASH over aad and ciphertext
    std::vector<uint8_t> S = GHASH(aad, ciphertext);

    // Tag = AES_K(J0) xor S
    std::vector<uint8_t> EkJ0(16);
    std::memcpy(EkJ0.data(), J0.data(), 16);
    aes.EncryptBlock(EkJ0.data());
    tag_out.resize(16);
    for (int i = 0; i < 16; ++i) tag_out[i] = EkJ0[i] ^ S[i];

    return ciphertext;
}

// Decrypt: returns plaintext if tag verifies, otherwise throws
std::vector<uint8_t> AES256_GCM::Decrypt(
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& tag)
{
    if (iv.size() != 12) {
        throw std::invalid_argument("Only 12-byte IV supported in this simple implementation");
    }
    if (tag.size() != 16) {
        throw std::invalid_argument("GCM tag must be 16 bytes");
    }
    std::vector<uint8_t> J0(16, 0);
    std::memcpy(J0.data(), iv.data(), 12);
    J0[15] = 1;

    // compute tag
    std::vector<uint8_t> S = GHASH(aad, ciphertext);
    std::vector<uint8_t> EkJ0(16);
    std::memcpy(EkJ0.data(), J0.data(), 16);
    aes.EncryptBlock(EkJ0.data());
    std::vector<uint8_t> tag_verify(16);
    for (int i = 0; i < 16; ++i) tag_verify[i] = EkJ0[i] ^ S[i];

    // constant-time compare
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<uint8_t>(tag_verify[i] ^ tag[i]);
    if (diff != 0) throw std::runtime_error("GCM authentication failed!");

    // recover plaintext only after tag passes
    std::vector<uint8_t> plaintext = GCTR(J0, ciphertext);
    return plaintext;
}
