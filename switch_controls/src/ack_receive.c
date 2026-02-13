#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "pcap_open.h"

#define LISTEN_IFACE "H1-eth1"

#define ETH_HDR_LEN 14

#define MARKER0 0xAA
#define MARKER1 0xFF
#define TRAILER_LEN 6

#define STOP_AFTER 100
#define MAX_RX     STOP_AFTER

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

struct recv_rec {
    uint32_t seq;
    uint64_t ts_ns;
};

static struct recv_rec recv_log[MAX_RX];
static size_t recv_count = 0;

static pcap_t *g_cap = NULL;

static void write_recv_csv(const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("fopen recv_times.csv");
        return;
    }

    fprintf(fp, "seq,ts_ns\n");
    for (size_t i = 0; i < recv_count; i++) {
        fprintf(fp, "%u,%llu\n",
                recv_log[i].seq,
                (unsigned long long)recv_log[i].ts_ns);
    }

    fclose(fp);
}

static void packet_handler(u_char *user,
                           const struct pcap_pkthdr *h,
                           const u_char *pkt)
{
    (void)user;

    if (!h || !pkt) return;
    if (h->caplen < ETH_HDR_LEN + TRAILER_LEN) return;

    const uint8_t *t = pkt + h->caplen - TRAILER_LEN;

    // market check
    if (t[0] != MARKER0 || t[1] != MARKER1) return;

    uint32_t seq;
    memcpy(&seq, t + 2, sizeof(seq));
    seq = ntohl(seq);

    uint64_t t_recv = now_ns();

    printf("receieved%zu/%d: seq=%u ts_ns=%llu\n",
           recv_count + 1, STOP_AFTER,
           seq,
           (unsigned long long)t_recv);
    fflush(stdout);

    if (recv_count < MAX_RX) {
        recv_log[recv_count].seq   = seq;
        recv_log[recv_count].ts_ns = t_recv;
        recv_count++;
    }

    if (recv_count >= STOP_AFTER && g_cap) {
        pcap_breakloop(g_cap);
    }
}

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    g_cap = open_pcap_handle(LISTEN_IFACE, 1, errbuf);
    if (!g_cap) {
        fprintf(stderr, "open_pcap_handle failed on %s: %s\n", LISTEN_IFACE, errbuf);
        return 1;
    }

    printf("Listening on %s... will stop after %d packets\n",
           LISTEN_IFACE, STOP_AFTER);

    int rc = pcap_loop(g_cap, -1, packet_handler, NULL);
    if (rc < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(g_cap));
    }

    pcap_close(g_cap);
    g_cap = NULL;

    write_recv_csv("recv_times.csv");
    printf("Wrote recv_times.csv with %zu rows\n", recv_count);

    return 0;
}