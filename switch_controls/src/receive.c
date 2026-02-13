#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "pcap_open.h"

#define LISTEN_IFACE "H2-eth0"
#define SEND_IFACE   "H2-eth1"

#define ETH_HDR_LEN 14

#define MARKER0 0xAA
#define MARKER1 0xFF
#define TRAILER_LEN 6

static pcap_t *sendh = NULL;


static void send_ack(uint32_t seq, const uint8_t *rx_pkt) // send ack frame to the H1
{
    uint8_t out[ETH_HDR_LEN + TRAILER_LEN]; // output buffer for ack packet

    // dst mac
    memcpy(out + 0, rx_pkt + 6, 6);
    // src mac
    memcpy(out + 6, rx_pkt + 0, 6);

    out[12] = 0x88;
    out[13] = 0xB5;

    // marker for trailer
    out[ETH_HDR_LEN + 0] = MARKER0;
    out[ETH_HDR_LEN + 1] = MARKER1;

    uint32_t net = htonl(seq); // convert to network bytes and copy into eth frame
    memcpy(out + ETH_HDR_LEN + 2, &net, sizeof(net));

    if (pcap_sendpacket(sendh, out, sizeof(out)) != 0) {
        fprintf(stderr, "ACK send failed: %s\n", pcap_geterr(sendh));
    }
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt){

    if (h->caplen < ETH_HDR_LEN + TRAILER_LEN)
        return;

    const uint8_t *t = pkt + h->caplen - TRAILER_LEN; // find trailer

    //printf("checking marker");
    if (t[0] != MARKER0 || t[1] != MARKER1){
        printf("no marker");
        return;
    }
    printf("marker present");

    uint32_t seq; // extract seq no
    memcpy(&seq, t + 2, sizeof(seq));
    seq = ntohl(seq);

    printf("packet seq=%u\n", seq);

    send_ack(seq, pkt);
}

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *cap = open_pcap_handle(LISTEN_IFACE, 1, errbuf);
    if (!cap) {
        fprintf(stderr, "Failed to open capture handle on %s: %s\n",
                LISTEN_IFACE, errbuf);
        return 1;
    }

    sendh = open_pcap_handle(SEND_IFACE, 0, errbuf);
    if (!sendh) {
        fprintf(stderr, "Failed to open send handle on %s: %s\n",
                SEND_IFACE, errbuf);
        pcap_close(cap);
        return 1;
    }

    printf("Listening on %s…\n", LISTEN_IFACE);

    if (pcap_loop(cap, -1, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cap));
    }

    pcap_close(cap);
    pcap_close(sendh);
    return 0;
}
