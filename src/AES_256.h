#ifndef AES_256_H
#define AES_256_H

#include <array>
#include <cstdint>
#include <vector>

class AES256 {
public:
    AES256(const std::vector<uint8_t>& key);
    void EncryptBlock(uint8_t* block) const;
    void DecryptBlock(uint8_t* block) const;

private:
    std::array<uint8_t, 240> roundKeys; // 240 bytes for AES-256

    void KeyExpansion(const std::vector<uint8_t>& key);
    void AddRoundKey(uint8_t state[4][4], int round) const;
    void SubBytes(uint8_t state[4][4]) const;
    void ShiftRows(uint8_t state[4][4]) const;
    void MixColumns(uint8_t state[4][4]) const;

    void InvSubBytes(uint8_t state[4][4]) const;
    void InvShiftRows(uint8_t state[4][4]) const;
    void InvMixColumns(uint8_t state[4][4]) const;

    static uint8_t xtime(uint8_t x);
    static uint8_t Multiply(uint8_t x, uint8_t y);

    static const uint8_t sbox[256];
    static const uint8_t inv_sbox[256];
    static const uint8_t Rcon[15];
};

#endif
