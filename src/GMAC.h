#ifndef GMAC_H
#define GMAC_H

#include "AES_256.h"
#include "GCM.h"
#include <vector>
#include <cstdint>

class AES256_GMAC {
public:
    AES256_GMAC(const std::vector<uint8_t>& key);
    std::vector<uint8_t> GenerateTag(
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& aad);

private:
    AES256_GCM gcm;
};

#endif
