#include "switch1.h"
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
#include <ctype.h>
#include <errno.h>

#define ETHERNET_HEADER_LEN 14
#define ID_TRAILER_LEN 6

static unsigned long packet_count = 0;

const char *csv_path = "../data/algorithm_data/algorithm_experiment_timing.csv";

// ---- shift to a new file?
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline uint64_t dt_ns(uint64_t t0, uint64_t t1) { return t1 - t0; }

static inline void nonce_from_counter(uint8_t *nonce, uint8_t nonce_len, uint64_t counter)
{
    // zero everything
    memset(nonce, 0, nonce_len);

    // write counter into the nonce len bytes
    uint8_t n = nonce_len;
    uint8_t bytes = (n >= 8) ? 8 : n;

    for (uint8_t i = 0; i < bytes; i++) {
        nonce[n - 1 - i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }
}

int handle_authenticate(ctx_t *ctx, const struct pcap_pkthdr *header, const u_char *packet)
{
    const profile_t *p = ctx->profile;
    if (!p) return 0;

    uint64_t t_crypto0 = now_ns();
    uint8_t nonce[32];
    const uint8_t *nonce_ptr = NULL;
    uint8_t nonce_len = p->nonce_len;
    if (nonce_len > 0) {
        if (nonce_len > sizeof(nonce)) return 0;
        nonce_from_counter(nonce, nonce_len, ctx->nonce_counter++);
        nonce_ptr = nonce;
    } else {
        nonce_ptr = NULL;
    }

    uint8_t tag[64];
    size_t tag_len = 0;
    // change to match AEAD authenticate everything except the trailer
    size_t protected_len = header->len - ID_TRAILER_LEN;
    // compute the tag and store in tag

    if (!auth_compute_tag(p, &ctx->crypto, ctx->crypto.aead_ctx, packet, protected_len, nonce_ptr, nonce_len, tag, sizeof(tag), &tag_len)) return 0;

    uint64_t t_crypto1 = now_ns();
    ctx->crypto_last_ns = dt_ns(t_crypto0, t_crypto1);
    // add extension to packet with new tag
    size_t new_len = header->len + ext_len(nonce_len, (uint8_t)tag_len);
    uint8_t *out = malloc(new_len);
    if (!out) return 0;

    size_t written = ext_append(out, new_len, packet, header->len, p->profile_id, nonce_ptr, nonce_len, tag, (uint8_t)tag_len);
    if (written == 0) { free(out); return 0; }

//    printf("packet tagged and send\n");
    if (pcap_sendpacket(ctx->send_handle, out, (int)written) != 0){
        fprintf(stderr, "send failed: %s\n", pcap_geterr(ctx->send_handle));
        free(out);
        return 0;
    }

    free(out);
    return 1;
}

int handle_verify(ctx_t *ctx, const struct pcap_pkthdr *header, const u_char *packet){
    const profile_t *p = ctx->profile;

    // setup nonce and key, parse the extenson footer and calculate the tag and compare
    const uint8_t *nonce = NULL;
    const uint8_t *tag   = NULL;
    size_t original_len  = 0;

    if (!ext_parse_footer_fixed(packet, header->len,p->profile_id, p->nonce_len, p->tag_len,
    &nonce, &tag, &original_len))
        return 0;

    // similarly copy the aead to not authenticate the trailer (only so they match)
    size_t protected_len = original_len - ID_TRAILER_LEN;

    uint64_t t_crypto0 = now_ns();
    if (!auth_verify_tag(p, &ctx->crypto, ctx->crypto.aead_ctx, packet, protected_len, nonce, p->nonce_len, tag, p->tag_len)){
        printf("*******     unable to verify packet    *******\n");
        return 0;
    }
    uint64_t t_crypto1 = now_ns();
    ctx->crypto_last_ns = dt_ns(t_crypto0, t_crypto1);

//    printf("packet successfully verified using %s and sending onwards\n",alg_to_str(p->alg));
    if (pcap_sendpacket(ctx->send_handle, packet, (int)original_len) != 0){
        return 0;
    }
    return 1;

}

int handle_aead_encrypt(ctx_t *ctx, const struct pcap_pkthdr *header, const u_char *packet)
{
    const profile_t *p = ctx->profile;
    if (!p || !header || !packet) return 0;

    // allocate header as aad
    if (header->len < ETHERNET_HEADER_LEN + ID_TRAILER_LEN) return 0;
    size_t protected_len = header->len - ID_TRAILER_LEN; // encrypting all except the id trailer, so that it is visible to script calculating the elapsed time
    const uint8_t *aad = (const uint8_t *)packet;
    size_t aad_len = ETHERNET_HEADER_LEN;

    // everything after is plaintext
    size_t pt_off = ETHERNET_HEADER_LEN;
    size_t pt_len = protected_len - pt_off;

    // allocate output bytes
    size_t footer_len = ext_len(p->nonce_len, p->tag_len);
    size_t out_len_cap = header->len + footer_len;

    uint8_t out_buf[2048]; // allocate buffer for packet
    if (out_len_cap > sizeof(out_buf)) return 0;

    memcpy(out_buf, packet, header->len);

    // generate nonce
    uint64_t t_crypto0 = now_ns();
    uint8_t nonce[32];
//    const uint8_t *nonce_ptr = NULL;
    nonce_from_counter(nonce, (uint8_t)p->nonce_len, ctx->nonce_counter++);

    // encrypt payload region, authenticate AAD header region
    uint8_t tag[16];
    size_t tag_len = 0;

    if (!aead_encrypt_inplace(p, &ctx->crypto, aad, aad_len, out_buf + pt_off, pt_len, nonce, p->nonce_len,
            tag, sizeof(tag), &tag_len)){
        return 0;
    }

    uint64_t t_crypto1 = now_ns();
    ctx->crypto_last_ns = dt_ns(t_crypto0, t_crypto1);

    // append extension field
    size_t new_len = ext_append(out_buf, sizeof(out_buf), out_buf, header->len, p->profile_id, nonce, (uint8_t)p->nonce_len, tag, (uint8_t)tag_len);

    if (new_len == 0) {
        printf("ext_append failed\n");
        return 0;
    }

    // send onwards
    if (pcap_sendpacket(ctx->send_handle, out_buf, (int)new_len) != 0) {
        printf("pcap_sendpacket failed\n");
        return 0;
    }

//    printf("packet AEAD-encrypted using %s (sent len=%zu)\n", alg_to_str(p->alg), new_len);
    return 1;
}

int handle_aead_decrypt_verify(ctx_t *ctx, const struct pcap_pkthdr *header, const u_char *packet)
{
    const profile_t *p = ctx->profile;
    if (!p || !header || !packet) return 0;

    // parse footer to recover nonce+tag
    const uint8_t *nonce = NULL;
    const uint8_t *tag   = NULL;
    size_t original_len  = 0;

    if (!ext_parse_footer_fixed(packet, header->len, p->profile_id, p->nonce_len, p->tag_len, &nonce, &tag, &original_len)){
        printf("ext_parse_footer_fixed failed\n");
        return 0;
    }

    if (original_len < ETHERNET_HEADER_LEN + ID_TRAILER_LEN) return 0;
    size_t protected_len = original_len - ID_TRAILER_LEN; // similarly with the decrypt, only the packet and not the id trailer

    // copy the original frame into buffer
    uint8_t buf[2048];
    if (original_len > sizeof(buf)) return 0;
    memcpy(buf, packet, original_len);

    // aad = ethernet header
    const uint8_t *aad = buf;
    size_t aad_len = ETHERNET_HEADER_LEN;
    size_t ct_off = ETHERNET_HEADER_LEN; // offset, anything after header is ciphertext
    size_t ct_len = protected_len - ct_off;

    uint64_t t_crypto0 = now_ns();
    // decrypt and verify tag
    if (!aead_decrypt_verify_inplace(p, &ctx->crypto, aad, aad_len, buf + ct_off, ct_len, nonce, p->nonce_len, tag, p->tag_len)){
        printf("******* AEAD verify/decrypt failed (%s) *******\n", alg_to_str(p->alg));
        return 0;
    }
    uint64_t t_crypto1 = now_ns();
    ctx->crypto_last_ns = dt_ns(t_crypto0, t_crypto1);

//    printf("packet AEAD verified+decrypted using %s and sending onwards\n", alg_to_str(p->alg));

    // send only the original frame
    if (pcap_sendpacket(ctx->send_handle, buf, (int)original_len) != 0) {
        printf("pcap_sendpacket failed\n");
        return 0;
    }

    return 1;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    ctx_t *ctx = (ctx_t *)user;
    if (!is_goose(packet, header->caplen)) return;
    packet_count ++;

//    const profile_t *p = ctx->profile;
    uint64_t t_total0 = now_ns();
    int forwarded = ctx->action ? ctx->action(ctx, header, packet) : 0;
    uint64_t t_total1 = now_ns();
    ctx->total_last_ns = dt_ns(t_total0, t_total1);
//    ctx->timing_sum_ns += ctx->total_last_ns;
//    printf("Packet: %lu switch processing time: %.3f us\n", packet_count, (double)ctx->total_last_ns / 1e3);

//    if (forwarded) {
//        fprintf(ctx->csv, "%s, %s, %s, %lu, %lu\n", sw_to_str(ctx->sw_id), alg_to_str(ctx->profile->alg), mode_to_str(ctx->profile->mode),
//            ctx->crypto_last_ns, ctx->total_last_ns);
//        ctx->timing_count++;
//        if (ctx->timing_count == 50) {
//            double avg_us = (double)ctx->timing_sum_ns / 50.0 / 1e3;
//            printf("Avg switch processing time (last 50):%.3f us\n", avg_us);
//            ctx->timing_sum_ns = 0;
//            ctx->timing_count = 0;
//        }
//    }
}

static int choose_action(ctx_t *ctx) {
    const profile_t *p = ctx->profile;
    if (!p) return 0;
    if (ctx->sw_id == SW_S1) {
        if (p->mode == PROFILE_MODE_MAC)  ctx->action = handle_authenticate;
        else if (p->mode == PROFILE_MODE_AEAD) ctx->action = handle_aead_encrypt;
        else return 0;
    } else if (ctx->sw_id == SW_S2) {
        if (p->mode == PROFILE_MODE_MAC)  ctx->action = handle_verify;
        else if (p->mode == PROFILE_MODE_AEAD) ctx->action = handle_aead_decrypt_verify;
        else return 0;
    } else {
        return 0;
    }
    return 1;
}

static const char* mode_to_str(profile_mode_t m) {
    switch (m) {
        case PROFILE_MODE_AEAD: return "AEAD";
        case PROFILE_MODE_MAC:  return "MAC";
        default: return "UNKNOWN";
    }
}

static const char* sw_to_str(switch_id_t sw) {
    switch (sw) {
        case SW_S1:    return "S1";
        case SW_S2:    return "S2";
        case SW_EXPER: return "EXPER";
        default:       return "SW?";
    }
}

int main(int argc, char *argv[])
{
    ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *capture_iface = NULL;
    const char *send_iface    = NULL;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <sw:1|2|3> <profile_id:0-9>\n", argv[0]);
        return 1;
    }

    // --- switch selection implies behaviour ---
    if (strcmp(argv[1], "1") == 0) {
        ctx.sw_id = SW_S1;
        capture_iface = "S1-eth1";
        send_iface    = "S1-eth2";
    } else if (strcmp(argv[1], "2") == 0) {
        ctx.sw_id = SW_S2;
        capture_iface = "S2-eth1";
        send_iface    = "S2-eth2";
    } else if (strcmp(argv[1], "3") == 0) {
        ctx.sw_id = SW_S1;
        capture_iface = "enp1s0";
        send_iface    = "enp2s0";
    } else if (strcmp(argv[1], "4") == 0) {
        ctx.sw_id = SW_S2;
        capture_iface = "enp1s0";
        send_iface    = "enp2s0";
    } else {
        fprintf(stderr, "Invalid <sw>: %s (expected 1,2,3)\n", argv[1]);
        return 1;
    }

    // argv[2] = profile id as a single digit '0'..'9'
    if (argv[2][0] == '\0' || argv[2][1] != '\0' || argv[2][0] < '0' || argv[2][0] > '9') {
        fprintf(stderr, "profile_id must be a single digit 0-9\n");
        return 1;
    }
    uint8_t prof_id = (uint8_t)(argv[2][0] - '0');

    ctx.profile = profile_lookup(prof_id);
    if (!ctx.profile) {
        fprintf(stderr, "cs profile %u not found\n", prof_id);
        return 1;
    }

    // initalise crypto context and zero nonce
    if (!profile_crypto_init(&ctx.crypto, ctx.profile)) {
        fprintf(stderr, "profile_crypto_init failed\n");
        return 1;
    }
    ctx.nonce_counter = 0;


    // open CSV, write header only if file is empty
    ctx.csv = fopen(csv_path, "a+");
    if (!ctx.csv) {
        fprintf(stderr, "fopen(%s) failed: %s\n", csv_path, strerror(errno));
        return 1;
    }
    fseek(ctx.csv, 0, SEEK_END);
    if (ftell(ctx.csv) == 0) {
        fprintf(ctx.csv, "sw,alg,mode,crypto_ns,total_ns\n");
        fflush(ctx.csv);
    }

    // open pcap handles
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *capture_handle = open_pcap_handle(capture_iface, 1, errbuf);
    if (!capture_handle) {
        fclose(ctx.csv);
        return 1;
    }

    ctx.send_handle = open_pcap_handle(send_iface, 0, errbuf);
    if (!ctx.send_handle) {
        pcap_close(capture_handle);
        fclose(ctx.csv);
        return 1;
    }

    // choose the packet action/alg based on sw + mode
    if (!choose_action(&ctx)) {
        fprintf(stderr, "Unable to choose handler for sw=%d mode=%d\n",
                (int)ctx.sw_id, (int)ctx.profile->mode);
        pcap_close(capture_handle);
        pcap_close(ctx.send_handle);
        fclose(ctx.csv);
        return 1;
    }

    printf("Switch=%s (%s -> %s), profile=%u (%s), mode=%s\n",
           (ctx.sw_id == SW_S1 ? "S1/apply" : "S2/verify"),
           capture_iface, send_iface,
           ctx.profile->profile_id,
           alg_to_str(ctx.profile->alg),
           mode_to_str(ctx.profile->mode));

    if (pcap_loop(capture_handle, 0, packet_handler, (u_char *)&ctx) < 0) {
        fprintf(stderr, "Error in capture loop: %s\n", pcap_geterr(capture_handle));
    }

    // cleanup
    pcap_close(capture_handle);
    pcap_close(ctx.send_handle);
    fflush(ctx.csv);
    fclose(ctx.csv);
    profile_crypto_cleanup(&ctx.crypto);

    return EXIT_SUCCESS;
}
