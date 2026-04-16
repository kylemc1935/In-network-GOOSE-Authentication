#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include "pcap_open.h"

// send script used to inject GOOSE packets into the network, packets are read in and strored in memory to minimise
// delay between packets

// change based on device and port listneing on -------
#define SEND_IFACE "H1-eth0"
// --------------------------

#define PCAP_FILE  "../sample_goose_packets.pcap"
#define ETH_HDR_LEN 14
#define MARKER0 0xAA
#define MARKER1 0xFF
#define TRAILER_LEN 6  // 2 marker + 4 seq

// 1,000,000 is 1ms
// #define SEND_DELAY_NS 0ULL
#define SEND_DELAY_NS 1000000ULL

#define MAX_PKTS 200000
#define MAX_FRAME 2048  // safety cap for in memory frames and out buffer

struct send_rec {  // struct to store timestamp and sequence number
    uint32_t seq;
    uint64_t ts_ns;
};

// pcap preload for faster sending
struct frame { // frame for the packet in memeory
    uint16_t len;
    uint8_t  data[MAX_FRAME];
};

static struct send_rec send_log[MAX_PKTS]; // struct to store all packets
static size_t send_count = 0;
static struct frame *frames = NULL;
static size_t nframes = 0;
#define MAX_CAPACITY 160 // 160 packets in this file, can adjust based on file used

static inline uint64_t now_ns(void){ // time function
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void nsleep(uint64_t ns){ // delay function
    if (ns == 0) return;
    struct timespec req;
    req.tv_sec  = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);
    nanosleep(&req, NULL);
}

static int get_iface_mac(const char *ifname, uint8_t mac[6]){ // mac address for the interface
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return 0;
    }

    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 1;
}


static void load_pcap_frames(const char *file) // open pcap file and load in frames
{
    char errbuf[PCAP_ERRBUF_SIZE]; // opne pcap file and allocate memory
    pcap_t *pc = pcap_open_offline(file, errbuf);
    if (!pc) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        exit(1);
    }
    frames = calloc(MAX_CAPACITY, sizeof(struct frame));
    if (!frames) {
        fprintf(stderr, "calloc failed\n");
        exit(1);
    }

    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int next;
    size_t i = 0;

    // iterate through pcap file and copy into memory
    while ((next = pcap_next_ex(pc, &hdr, &pkt)) == 1) {
        frames[i].len = (uint16_t)hdr->caplen;
        memcpy(frames[i].data, pkt, hdr->caplen);
        i++;
    }

    pcap_close(pc);
    nframes = i;

    if (nframes == 0) {
        fprintf(stderr, "No frames loaded\n");
        exit(1);
    }

    printf("Loaded %zu frames from %s\n", nframes, file);
}

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // preload the PCAP into mem for speed, then can loop through them indefinitely
    load_pcap_frames(PCAP_FILE);

    pcap_t *sendh = open_pcap_handle(SEND_IFACE, 0, errbuf);
    if (!sendh) {
        fprintf(stderr, "Failed to open send interface %s: %s\n", SEND_IFACE, errbuf);
        return 1;
    }

    uint8_t src_mac[6];
    if (!get_iface_mac(SEND_IFACE, src_mac)) {
        fprintf(stderr, "Failed to read MAC of %s\n", SEND_IFACE);
        return 1;
    }
    printf("Using src MAC %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    // reuse a single output buffer (no per packet malloc/free)
    uint8_t out[MAX_FRAME + TRAILER_LEN];

    uint32_t seq = 0;
    unsigned long sent = 0;

    // loop over preloaded frames until MAX_PKTS is reached
    size_t idx = 0;
    while (sent < MAX_PKTS) {
        const struct frame *f = &frames[idx];
        idx++;
        if (idx == nframes) idx = 0; // wrap around

        size_t base_len = f->len;
        size_t new_len  = base_len + TRAILER_LEN;

        // copy base frame
        memcpy(out, f->data, base_len);

        // append trailer marker + seq
        out[base_len + 0] = MARKER0;
        out[base_len + 1] = MARKER1;

        uint32_t cur_seq = seq++;
        uint32_t seq_net = htonl(cur_seq);
        memcpy(out + base_len + 2, &seq_net, sizeof(seq_net));

        if (pcap_sendpacket(sendh, out, (int)new_len) != 0) { // send
            fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(sendh));
            break;
        }

        sent++;

//        printf("Sent packet: %lu \n", sent);

        nsleep(SEND_DELAY_NS);
    }

    pcap_close(sendh);

    printf("Done. Sent %lu packets\n", sent);

    free(frames);
    return 0;
}
