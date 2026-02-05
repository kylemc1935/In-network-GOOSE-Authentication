#ifndef PCAP_OPEN
#define PCAP_OPEN
#include <sys/types.h>
#include <pcap.h>

pcap_t *open_pcap_handle(const char *iface, int want_in_direction, char errbuf[PCAP_ERRBUF_SIZE]);

#endif