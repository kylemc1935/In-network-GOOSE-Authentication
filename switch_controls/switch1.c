#include <pcap.h>
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
#include <openssl/rand.h>

static const uint8_t KEY_TEST[] = "testingkey";

static const profile_t *ACTIVE_PROFILE = NULL;

#define TAG_LEN 32
#define ETHERNET_HEADER_LEN 14
const char *CAPTURE_IFACE = NULL;
const char *SEND_IFACE = NULL;
int packet_handler_mode;
pcap_t *send_handle = NULL;
static unsigned long packet_count = 0;

void print_packet(const u_char *packet, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}


void handle_authenticate(const struct pcap_pkthdr *header, const u_char *packet)
{
    packet_count++;
    const profile_t *p = ACTIVE_PROFILE;
    if (!p) return;

    // nonce creating - needs tweaking
    uint8_t nonce[32];
    if (p->nonce_len > sizeof(nonce)) return;
    if (RAND_bytes(nonce, p->nonce_len) != 1) return;

    uint8_t tag[64];
    size_t tag_len = 0;
    // compute the tag and store in tag
    if (!auth_compute_tag(p, packet, header->len, nonce, p->nonce_len, tag, sizeof(tag), &tag_len)) return;

    // evry 20 packets insert fake tag to ensure the handle verify works correctly
    if (packet_count % 20 == 0) {
        memset(tag, 0, tag_len); // fake tag
        printf("Injected fake tag on packet %lu\n", packet_count);
    }

    // add extension to packet with new tag
    size_t new_len = header->len + ext_len(p->nonce_len, (uint8_t)tag_len);
    uint8_t *out = malloc(new_len);
    if (!out) return;

    size_t written = ext_append(out, new_len, packet, header->len, p->profile_id, nonce, p->nonce_len, tag, (uint8_t)tag_len);
    if (written == 0) { free(out); return; }

    printf("packet tagged and send");
    if (pcap_sendpacket(send_handle, out, (int)written) != 0)
        fprintf(stderr, "send failed: %s\n", pcap_geterr(send_handle));

    free(out);
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
    pcap_sendpacket(send_handle, packet, (int)original_len);
    return 1;

}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("packet has arrived of length:  %u\n", header->len);
    //print_packet(packet, header->len);
    // mode 1 -> authenticate
    // mode 2 -> verify - might need tweaking, come back to this
    if (packet_handler_mode == 1) {
        handle_authenticate(header, packet);
    } else if (packet_handler_mode == 2) {
        handle_verify(header, packet);
    }
}

int main(int argc, char *argv[]){

    if (argc < 2) {
        printf("usage....to be added");
        return 1;
    }
    if (strcmp(argv[1], "1") == 0) {
        CAPTURE_IFACE = "S1-eth1";
        SEND_IFACE    = "S1-eth2";
        packet_handler_mode = 1;
    } else if (strcmp(argv[1], "2") == 0) {
        CAPTURE_IFACE = "S2-eth1";
        SEND_IFACE    = "S2-eth2";
        packet_handler_mode = 2;
    } else {
        fprintf(stderr, "Invalid argument: %s (use 1 or 2)\n", argv[1]);
        return 1;
    }

    // active profile setup, to be fixed
    ACTIVE_PROFILE = profile_lookup(4);  // hardcoded for now
    if (!ACTIVE_PROFILE) {
        fprintf(stderr, "Active profile not found\n");
        return 1;
    }

    //configure capture handle   - could shift this to another file? makes this important file congested and long ???????
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture_handle = pcap_create(CAPTURE_IFACE, errbuf);
    if (capture_handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_set_buffer_size(capture_handle, 2*1024*1024) != 0) { //set buffer size to 2MB
        fprintf(stderr, "Error setting buffer size: %s\n", pcap_geterr(capture_handle));
    }

    if (pcap_set_immediate_mode(capture_handle, 1) != 0) { //set to immediate mode
        fprintf(stderr, "Error setting immediate mode: %s\n", pcap_geterr(capture_handle));
    }

    if (pcap_set_timeout(capture_handle, 10) != 0) {
        fprintf(stderr, "Error setting capture timeout: %s\n", pcap_geterr(capture_handle));
    }

    if (pcap_activate(capture_handle) < 0) { //activate hanlde
        fprintf(stderr, "Error activating capture handle: %s\n", pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        exit(EXIT_FAILURE);
    }

    if (pcap_setdirection(capture_handle, PCAP_D_IN) != 0) { //set direction one way for this demo
        fprintf(stderr, "Error setting direction: %s\n", pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        return EXIT_FAILURE;
    }

    //configure the send handle similar to capture handle   - could also shift...
    send_handle = pcap_create(SEND_IFACE, errbuf);
    if (send_handle == NULL) {
        fprintf(stderr, "pcap_create for send_handle failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_set_buffer_size(send_handle, 2*1024*1024) != 0) {
        fprintf(stderr, "Error setting send_handle buffer size: %s\n", pcap_geterr(send_handle));
    }
    if (pcap_set_immediate_mode(send_handle, 1) != 0) {
        fprintf(stderr, "Error setting send_handle immediate mode: %s\n", pcap_geterr(send_handle));
    }
    if (pcap_set_timeout(send_handle, 10) != 0) {
        fprintf(stderr, "Error setting send_handle timeout: %s\n", pcap_geterr(send_handle));
    }
    if (pcap_activate(send_handle) < 0) {
        fprintf(stderr, "Error activating send_handle: %s\n", pcap_geterr(send_handle));
        pcap_close(send_handle);
        exit(EXIT_FAILURE);
    }

    // start packet capture
    if (pcap_loop(capture_handle, 0, packet_handler, NULL) < 0){
        fprintf(stderr, "Error in capture loop: %s\n", pcap_geterr(capture_handle));
    }

    pcap_close(capture_handle);
    pcap_close(send_handle);

    return EXIT_SUCCESS;
}