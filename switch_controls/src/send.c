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

#define PCAP_FILE  "../sample_goose_packets.pcap"
#define SEND_IFACE "H1-eth0"
static const uint8_t hardcoded_dst_mac[6] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02   // example GOOSE multicast MAC
};

#define ETH_HDR_LEN 14

#define MARKER0 0xAA
#define MARKER1 0xFF
#define TRAILER_LEN 6  // 2 marker + 4 seq

#define SEND_DELAY_NS 1000000ULL  // 1 ms


static void nsleep(uint64_t ns) // delay function
{
    struct timespec req;
    req.tv_sec  = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);
    nanosleep(&req, NULL);
}

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#define MAX_PKTS 200000

struct send_rec {
    uint32_t seq;
    uint64_t ts_ns;
};

static struct send_rec send_log[MAX_PKTS];
static size_t send_count = 0;


static pcap_t *open_pcap_offline_file(const char *file) // open file for packets
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(file, errbuf);
    if (!p) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        exit(1);
    }
    return p;
}

static int get_iface_mac(const char *ifname, uint8_t mac[6])
{
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

static void dump_trailer(const uint8_t *pkt, size_t len)
{
    if (len < TRAILER_LEN) return;

    const uint8_t *t = pkt + len - TRAILER_LEN;

    /*printf("Trailer: ");
    for (size_t i = 0; i < TRAILER_LEN; i++)
        printf("%02x ", t[i]);*/

    if (t[0] == MARKER0 && t[1] == MARKER1) {
        uint32_t seq;
        memcpy(&seq, t + 2, sizeof(seq));
        printf("(seq=%u)", ntohl(seq));
    } else {
        printf("(bad marker)");
    }
    printf("\n");
}


int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *sendh = open_pcap_handle(SEND_IFACE, 0, errbuf);
    if (!sendh) {
        fprintf(stderr, "Failed to open send interface %s\n", SEND_IFACE);
        return 1;
    }

    uint8_t src_mac[6];
    if (!get_iface_mac(SEND_IFACE, src_mac)) {
        fprintf(stderr, "Failed to read MAC of %s\n", SEND_IFACE);
        return 1;
    }
    printf("Using src MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
           src_mac[0], src_mac[1], src_mac[2],
           src_mac[3], src_mac[4], src_mac[5]);

    uint32_t seq = 0;
    unsigned long sent = 0;

    pcap_t *pcap = open_pcap_offline_file(PCAP_FILE);

    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;

    while ((rc = pcap_next_ex(pcap, &hdr, &pkt)) == 1) {
        if (hdr->caplen < ETH_HDR_LEN)
            continue;

        size_t base_len = hdr->caplen;
        size_t new_len  = base_len + TRAILER_LEN;

        uint8_t *out = malloc(new_len);
        if (!out) {
            fprintf(stderr, "malloc failed\n");
            break;
        }

        memcpy(out, pkt, base_len);
        memcpy(out + 0, hardcoded_dst_mac, 6);
        memcpy(out + 6, src_mac, 6);


        out[base_len + 0] = MARKER0;
        out[base_len + 1] = MARKER1;

        uint64_t t_send = now_ns();

        uint32_t cur_seq = seq++;
        uint32_t seq_net = htonl(cur_seq);
        memcpy(out + base_len + 2, &seq_net, sizeof(seq_net));

        if (send_count < MAX_PKTS) {
            send_log[send_count].seq   = cur_seq;
            send_log[send_count].ts_ns = t_send;
            send_count++;
        }

        if (pcap_sendpacket(sendh, out, (int)new_len) != 0) {
            fprintf(stderr, "pcap_sendpacket failed: %s\n",
                    pcap_geterr(sendh));
            free(out);
            break;
        }

        dump_trailer(out, new_len);
        free(out);

        sent++;
        if (sent % 1000 == 0) {
            printf("sent %lu packets (last seq=%u)\n",
                   sent, seq - 1);
            fflush(stdout);
        }

        nsleep(SEND_DELAY_NS);
    }

    pcap_close(pcap);
    pcap_close(sendh);

    printf("Done. Sent %lu packets\n", sent);

    FILE *fp = fopen("send_times.csv", "w");
    if (!fp) {
        perror("fopen send_times.csv");
    } else {
        fprintf(fp, "seq,ts_ns\n");
        for (size_t i = 0; i < send_count; i++) {
            fprintf(fp, "%u,%llu\n",
                    send_log[i].seq,
                    (unsigned long long)send_log[i].ts_ns);
        }
        fclose(fp);
    }
    return 0;
}
