#include <linux/if_ether.h>
#include "ebpf_switch.h"

// ===== CONFIG: 2 physical ports =====
#define VETH_IN_PORT        0   // to GASF
#define VETH_RETURN_PORT    1   // from GASF
#define IN_PHYS_PORT        2   // ingress
#define OUT_PHYS_PORT       3   // egress
#define LOAD_PHYS_PORT      3   // external/load device (when using 2 physical ports, load port and output port are the same)

// ===== CONFIG: 3 physical ports =====
// #define VETH_IN_PORT        0
// #define VETH_RETURN_PORT    1
// #define IN_PHYS_PORT        2
// #define OUT_PHYS_PORT       3
// #define LOAD_PHYS_PORT     4   // external/load device

uint64_t prog(struct packet *pkt)
{
    // GOOSE - send to GASF
    if (pkt->metadata.in_port == IN_PHYS_PORT &&
        pkt->eth.h_proto == 47240)
    {
        return PORT + VETH_IN_PORT;
    }

    // non-GOOSE traffic - forward normally (or to external device)
    if (pkt->metadata.in_port == IN_PHYS_PORT)
    {
        return PORT + LOAD_PHYS_PORT;
    }

    // returning from GASF - forward to output port
    if (pkt->metadata.in_port == VETH_RETURN_PORT)
    {
        return PORT + OUT_PHYS_PORT;
    }

    return DROP;
}

char _license[] SEC("license") = "GPL";