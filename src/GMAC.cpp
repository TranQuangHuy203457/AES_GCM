#include "GMAC.h"

AES256_GMAC::AES256_GMAC(const std::vector<uint8_t>& key) 
    : gcm(key) {} 

std::vector<uint8_t> AES256_GMAC::GenerateTag(
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad)
{
    std::vector<uint8_t> empty_plaintext;
    std::vector<uint8_t> tag;
    gcm.Encrypt(iv, empty_plaintext, aad, tag);
    return tag;
}
