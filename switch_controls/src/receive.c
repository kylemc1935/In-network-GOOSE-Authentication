#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "pcap_open.h"

// simple receive script, that handles incoming GOOSE packets
// it extracts the experimental sequence number for debugging to ensure traversal works

// change based on the device and port listening on----
#define LISTEN_IFACE "H1-eth1"
// -----------------------

#define ETH_HDR_LEN 14
#define MARKER0 0xAA
#define MARKER1 0xFF
#define TRAILER_LEN 6
#define MAX_RECV 20000

//static pcap_t *sendh = NULL;

struct recv_rec {
    uint32_t seq;
    uint64_t ts_ns;
};

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt)
{
    uint64_t t_recv = now_ns();

    if (h->caplen < ETH_HDR_LEN + TRAILER_LEN)
        return;

    const uint8_t *t = pkt + h->caplen - TRAILER_LEN; // find trailer

    //printf("checking marker");
    if (t[0] != MARKER0 || t[1] != MARKER1){
        printf("no marker\n");
        return;
    }

    uint32_t seq; // extract seq no
    memcpy(&seq, t + 2, sizeof(seq));
    seq = ntohl(seq);

    printf("packet seq=%u\n", seq);

}

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *recvh = open_pcap_handle(LISTEN_IFACE, 1, errbuf);
    if (!recvh) {
        fprintf(stderr, "Failed to open capture handle on %s: %s\n", LISTEN_IFACE, errbuf);
        return 1;
    }

    printf("Listening on %s…\n", LISTEN_IFACE);

    if (pcap_loop(recvh, -1, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(recvh));
    }

    pcap_close(recvh);
    return 0;
}
