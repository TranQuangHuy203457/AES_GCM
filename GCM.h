#ifndef GCM_H
#define GCM_H

#include "AES_256.h"
#include <vector>
#include <cstdint>
#include <array>

class AES256_GCM {
public:
    AES256_GCM(const std::vector<uint8_t>& key);

    // Encrypt: returns ciphertext and writes 16-byte tag into tag_out
    std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        std::vector<uint8_t>& tag_out);

    // Decrypt: returns plaintext if tag valid, otherwise throws std::runtime_error
    std::vector<uint8_t> Decrypt(
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& tag);

private:
    AES256 aes;
    std::vector<uint8_t> H; // hash subkey = AES_K(0^128)

    // GHASH returns 128-bit value (16 bytes)
    std::vector<uint8_t> GHASH(
        const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& ciphertext) const;

    // Galois field multiplication in GF(2^128), both inputs 16 bytes, return 16 bytes
    std::vector<uint8_t> GaloisMultiply(
        const std::vector<uint8_t>& X,
        const std::vector<uint8_t>& Y) const;

    void PrecomputeHTable();

    // increment rightmost 32 bits (big-endian) of 16-byte counter in-place
    void Inc32(std::vector<uint8_t>& counter) const;

    // XOR a ^= b (both 16 bytes)
    static void XOR(std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

    // GCTR (AES-CTR) using initial counter block icb (16 bytes)
    std::vector<uint8_t> GCTR(const std::vector<uint8_t>& icb,
                              const std::vector<uint8_t>& input) const;

    // Precomputed V table for GHASH fast path when multiplying by H
    std::array<std::array<uint8_t, 16>, 128> Htable{};
};

#endif
