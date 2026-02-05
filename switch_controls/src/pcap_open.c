#include "pcap_open.h"
#include <stdio.h>

pcap_t *open_pcap_handle(const char *iface, int want_in_direction, char errbuf[PCAP_ERRBUF_SIZE])
{
    pcap_t *h = pcap_create(iface, errbuf);
    if (!h) return NULL;

    pcap_set_buffer_size(h, 2*1024*1024);
    pcap_set_immediate_mode(h, 1);
    pcap_set_timeout(h, 10);

    if (pcap_activate(h) < 0) {
        fprintf(stderr, "Error activating %s: %s\n", iface, pcap_geterr(h));
        pcap_close(h);
        return NULL;
    }

    if (want_in_direction && pcap_setdirection(h, PCAP_D_IN) != 0) {
        fprintf(stderr, "Error setting direction on %s: %s\n", iface, pcap_geterr(h));
        pcap_close(h);
        return NULL;
    }

    return h;
}
