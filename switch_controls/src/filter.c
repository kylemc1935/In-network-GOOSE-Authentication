#include "filter.h"

int is_goose(const unsigned char *pkt, unsigned int len)
{
    if (len < 14) {
        printf("Packet received is not GOOSE: frame too short (%u bytes)\n", len);
        return 0;
    }

    uint16_t ethertype = ((uint16_t)pkt[12] << 8) | pkt[13];

    if (ethertype != 0x88B8) {
        printf("Packet received is not GOOSE: ethertype 0x%04x\n", ethertype);
        return 0;
    }

    return 1;
}