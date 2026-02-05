#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include "filter.h"
#include "crypto/profiles.h"
#include "crypto/auth.h"
#include "crypto/extension.h"
#include "crypto/aead.h"
#include "pcap_open.h"
#include <openssl/rand.h>
#include <time.h>

typedef enum {
    SW_S1 = 1,
    SW_S2 = 2
} switch_id_t;

static switch_id_t sw_id;
static const profile_t *ACTIVE_PROFILE = NULL;
#define ETHERNET_HEADER_LEN 14
const char *CAPTURE_IFACE = NULL;
const char *SEND_IFACE = NULL;
pcap_t *send_handle = NULL;
static unsigned long packet_count = 0;
static int choose_action(void);

typedef int (*packet_action_fn)(const struct pcap_pkthdr*, const u_char*);
static packet_action_fn crypto_function = NULL;

void print_packet(const u_char *packet, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// ---- shift to a new file?

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static unsigned long timing_count = 0;
static uint64_t timing_sum_ns = 0;

int handle_authenticate(const struct pcap_pkthdr *header, const u_char *packet)
{
    packet_count++;
    const profile_t *p = ACTIVE_PROFILE;
    if (!p) return 0;

    // nonce creating - needs tweaking
    uint8_t nonce[32];
    if (p->nonce_len > sizeof(nonce)) return 0;
    if (RAND_bytes(nonce, p->nonce_len) != 1) return 0;

    uint8_t tag[64];
    size_t tag_len = 0;
    // compute the tag and store in tag
    if (!auth_compute_tag(p, packet, header->len, nonce, p->nonce_len, tag, sizeof(tag), &tag_len)) return 0;

    // evry 20 packets insert fake tag to ensure the handle verify works correctly
    if (packet_count % 20 == 0) {
        memset(tag, 0, tag_len); // fake tag
        //printf("Injected fake tag on packet %lu\n", packet_count);
    }

    // add extension to packet with new tag
    size_t new_len = header->len + ext_len(p->nonce_len, (uint8_t)tag_len);
    uint8_t *out = malloc(new_len);
    if (!out) return 0;

    size_t written = ext_append(out, new_len, packet, header->len, p->profile_id, nonce, p->nonce_len, tag, (uint8_t)tag_len);
    if (written == 0) { free(out); return 0; }

    printf("packet tagged and send");
    if (pcap_sendpacket(send_handle, out, (int)written) != 0){
        fprintf(stderr, "send failed: %s\n", pcap_geterr(send_handle));
        free(out);
        return 0;
    }

    free(out);
    return 1;
}

int handle_verify(const struct pcap_pkthdr *header, const u_char *packet){
    const profile_t *p = ACTIVE_PROFILE;

    // setup nonce and key, parse the extenson footer and calculate the tag and compare
    const uint8_t *nonce = NULL;
    const uint8_t *tag   = NULL;
    size_t original_len  = 0;

    if (!ext_parse_footer_fixed(packet, header->len,
                                p->profile_id, p->nonce_len, p->tag_len,
                                &nonce, &tag, &original_len))
        return 0;

    if (!auth_verify_tag(p, packet, original_len, nonce, p->nonce_len, tag, p->tag_len)){
        printf("*******     unable to verify packet    *******\n");
        return 0;
    }

    printf("packet successfully verified using %s and sending onwards\n",alg_to_str(p->alg));
    if (pcap_sendpacket(send_handle, packet, (int)original_len) != 0){
        return 0;
    }
    return 1;

}

int handle_aead_encrypt(const struct pcap_pkthdr *header, const u_char *packet)
{
    packet_count++;
    const profile_t *p = ACTIVE_PROFILE;
    if (!p || !header || !packet) return 0;

    // allocate header as aad
    if (header->len < ETHERNET_HEADER_LEN) return 0;
    const uint8_t *aad = (const uint8_t *)packet;
    size_t aad_len = ETHERNET_HEADER_LEN;

    // everything after is plaintext
    size_t pt_off = ETHERNET_HEADER_LEN;
    size_t pt_len = header->len - pt_off;

    // allocate output bytes
    size_t footer_len = ext_len(p->nonce_len, p->tag_len);
    size_t out_len_cap = header->len + footer_len;

    uint8_t out_buf[2048]; // allocate buffer for packet
    if (out_len_cap > sizeof(out_buf)) return 0;

    memcpy(out_buf, packet, header->len);

    // generate nonce - maybe use different library for this?
    uint8_t nonce[32];
    if (p->nonce_len > sizeof(nonce)) return 0;
    if (RAND_bytes(nonce, (int)p->nonce_len) != 1) return 0;

    // encrypt payload region, authenticate AAD header region
    uint8_t tag[16];
    size_t tag_len = 0;
    if (!aead_encrypt_inplace(p, aad, aad_len, out_buf + pt_off, pt_len, nonce, p->nonce_len,
            tag, sizeof(tag), &tag_len)){
        printf("AEAD encrypt failed\n");
        return 0;
    }

    // corrupt occassional tag to test decrypt response
    if (packet_count % 20 == 0) {
        memset(tag, 0, tag_len); // fake tag
        // printf("Injected fake tag on packet %lu\n", packet_count);
    }

    // append extension field
    size_t new_len = ext_append(out_buf, sizeof(out_buf), out_buf, header->len, p->profile_id, nonce, (uint8_t)p->nonce_len, tag, (uint8_t)tag_len);

    if (new_len == 0) {
        printf("ext_append failed\n");
        return 0;
    }

    // send onwards
    if (pcap_sendpacket(send_handle, out_buf, (int)new_len) != 0) {
        printf("pcap_sendpacket failed\n");
        return 0;
    }

    printf("packet AEAD-encrypted using %s (sent len=%zu)\n", alg_to_str(p->alg), new_len);
    return 1;
}

int handle_aead_decrypt_verify(const struct pcap_pkthdr *header, const u_char *packet)
{
    const profile_t *p = ACTIVE_PROFILE;
    if (!p || !header || !packet) return 0;

    // parse footer to recover nonce+tag
    const uint8_t *nonce = NULL;
    const uint8_t *tag   = NULL;
    size_t original_len  = 0;

    if (!ext_parse_footer_fixed(packet, header->len, p->profile_id, p->nonce_len, p->tag_len, &nonce, &tag, &original_len)){
        printf("ext_parse_footer_fixed failed\n");
        return 0;
    }

    // original_len is the authenticated+encrypted frame length
    if (original_len < ETHERNET_HEADER_LEN) return 0;

    // copy the original frame into buffer
    uint8_t buf[2048];
    if (original_len > sizeof(buf)) return 0;
    memcpy(buf, packet, original_len);

    // aad = ethernet header
    const uint8_t *aad = buf;
    size_t aad_len = ETHERNET_HEADER_LEN;
    size_t ct_off = ETHERNET_HEADER_LEN; // offset, anything after header is ciphertext
    size_t ct_len = original_len - ct_off;

    // decrypt and verify tag
    if (!aead_decrypt_verify_inplace(p, aad, aad_len, buf + ct_off, ct_len, nonce, p->nonce_len, tag, p->tag_len)){
        printf("******* AEAD verify/decrypt failed (%s) *******\n", alg_to_str(p->alg));
        return 0;
    }

    printf("packet AEAD verified+decrypted using %s and sending onwards\n", alg_to_str(p->alg));

    // send only the original frame
    if (pcap_sendpacket(send_handle, buf, (int)original_len) != 0) {
        printf("pcap_sendpacket failed\n");
        return 0;
    }

    return 1;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (!is_goose(packet, header->caplen)) return;

    uint64_t t0 = now_ns();
    //const profile_t *p = ACTIVE_PROFILE;

    int forwarded = crypto_function ? crypto_function(header, packet) : 0;
    uint64_t t1 = now_ns();

    if (forwarded) {
        timing_sum_ns += (t1 - t0);
        timing_count++;

        double avg_us = (double)timing_sum_ns / (double)timing_count / 1e3;
        printf("Avg switch processing time: %.3f us (n=%lu)\n", avg_us, timing_count);
        printf("just testing the debug");
        }
    }

static int choose_action(void) {
    const profile_t *p = ACTIVE_PROFILE;
    if (!p) return 0;

    if (sw_id == SW_S1) {
        if (p->mode == PROFILE_MODE_MAC)  crypto_function = handle_authenticate;
        else if (p->mode == PROFILE_MODE_AEAD) crypto_function = handle_aead_encrypt;
        else return 0;
    } else if (sw_id == SW_S2) {
        if (p->mode == PROFILE_MODE_MAC)  crypto_function = handle_verify;
        else if (p->mode == PROFILE_MODE_AEAD) crypto_function = handle_aead_decrypt_verify;
        else return 0;
    } else {
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        //usage(argv[0]);
        return 1;
    }

    // --- switch selection implies behaviour ---
    if (strcmp(argv[1], "1") == 0) {
        sw_id = SW_S1;
        CAPTURE_IFACE = "S1-eth1";
        SEND_IFACE    = "S1-eth2";
    } else if (strcmp(argv[1], "2") == 0) {
        sw_id = SW_S2;
        CAPTURE_IFACE = "S2-eth1";
        SEND_IFACE    = "S2-eth2";
    } else {
        fprintf(stderr, "Invalid <sw>: %s\n", argv[1]);
        //usage(argv[0]);
        return 1;
    }

    // argv[2] = profile id as a single digit '0'..'9'
    if (argv[2][0] == '\0' || argv[2][1] != '\0' || argv[2][0] < '0' || argv[2][0] > '9') {
        fprintf(stderr, "profile_id must be a single digit 0-9\n");
        return 1;
    }
    uint8_t prof_id = (uint8_t)(argv[2][0] - '0');

    ACTIVE_PROFILE = profile_lookup(prof_id);
    if (!ACTIVE_PROFILE) {
        fprintf(stderr, "Active profile %u not found\n", prof_id);
        return 1;
    }

    if (!choose_action()) {
        fprintf(stderr, "Unable to choose handler for sw=%d mode=%d\n", (int)sw_id, (int)ACTIVE_PROFILE->mode);
        return 1;
    }

    printf("Switch=%s (%s -> %s), profile=%u (%s), mode=%s\n",
           (sw_id == SW_S1 ? "S1/apply" : "S2/verify"),
           CAPTURE_IFACE, SEND_IFACE,
           ACTIVE_PROFILE->profile_id,
           alg_to_str(ACTIVE_PROFILE->alg),
           (ACTIVE_PROFILE->mode == PROFILE_MODE_AEAD ? "AEAD" : "MAC"));

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *capture_handle = open_pcap_handle(CAPTURE_IFACE, 1, errbuf);
    if (!capture_handle) return 1;

    send_handle = open_pcap_handle(SEND_IFACE, 0, errbuf);
    if (!send_handle) { pcap_close(capture_handle); return 1; }

    if (pcap_loop(capture_handle, 0, packet_handler, NULL) < 0)
        fprintf(stderr, "Error in capture loop: %s\n", pcap_geterr(capture_handle));

    pcap_close(capture_handle);
    pcap_close(send_handle);

    return EXIT_SUCCESS;
}