#include "filter.h"

int is_goose(const unsigned char *pkt, unsigned int len) {
    if (len < 14) return 0;
    uint16_t ethertype = ((uint16_t)pkt[12] << 8) | pkt[13];
    return ethertype == 0x88B8;
}