#ifndef SWITCH1_H
#define SWITCH1_H

#include <stdint.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include "crypto/profiles.h"

// switch toles for each one
typedef enum {
    SW_S1 = 1,
    SW_S2 = 2,
//    SW_EXPER = 3
} switch_id_t;

struct ctx;

// function for packet handler to use to select the appropriate function
typedef int (*packet_action_fn)(struct ctx *ctx,
                                const struct pcap_pkthdr *hdr,
                                const u_char *pkt);

// per switch runtime context, stores the data needed
typedef struct ctx {
    switch_id_t sw_id; // switch id
    const profile_t *profile; // crypogrphic profile
    pcap_t *send_handle;
    FILE *csv; // output csv for isolated crypto times

    packet_action_fn action; // packet handler function

    uint64_t crypto_last_ns;   // per packet crypto time
    uint64_t total_last_ns;    // time of total processing (crypto itself + extra handling associated with crypto)

    // nonce state
    uint64_t nonce_counter;
    uint8_t  nonce_prefix[32];
    uint8_t  nonce_prefix_len;

    // crypto context struct
    profile_crypto_t crypto;
} ctx_t;

// want to look at moving these but works for now
//static const char *mode_to_str(profile_mode_t m);
//static const char *sw_to_str(switch_id_t sw);

#endif
