#include "utils/csum.h"

uint8_t compute_checksum(char *buf, uint32_t len)
{
    uint8_t csum = 0;
    for (uint32_t i = 0; i < len; ++i)
        csum += buf[i];
    return csum;
}
