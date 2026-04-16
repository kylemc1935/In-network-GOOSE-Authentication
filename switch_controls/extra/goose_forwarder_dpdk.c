#include <linux/if_ether.h>
#include "ebpf_switch.h"

// ===== CONFIG: 2 physical ports =====
#define IN_PHYS_PORT    0
#define OUT_PHYS_PORT   1
#define LOAD_PHYS_PORT  1
#define TAP_PORT        2

// ===== CONFIG: 3 physical ports =====
// #define IN_PHYS_PORT    0
// #define OUT_PHYS_PORT   1
// #define LOAD_PHYS_PORT  2 // addtional 3rd port, so TAP indice is incremented, may require chaning based on BPFabric setup, the CLI will show the ordering once setup
// #define TAP_PORT        3

uint64_t prog(struct packet *pkt)
{
    // GOOSE arriving from incoming physical port - TAP for auth
    if (pkt->metadata.in_port == IN_PHYS_PORT &&
        pkt->eth.h_proto == 47240)
    {
        return PORT + TAP_PORT;
    }

    // all other traffic - forward normally
    if (pkt->metadata.in_port == IN_PHYS_PORT)
    {
        return PORT + LOAD_PHYS_PORT;
    }

    // packets returning from TAP - forward to output port
    if (pkt->metadata.in_port == TAP_PORT)
    {
        return PORT + OUT_PHYS_PORT;
    }

    return DROP;
}
char _license[] SEC("license") = "GPL";
