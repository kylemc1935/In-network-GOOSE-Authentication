#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

static const uint8_t KEY[] = "testingkey";
static const int KEY_LEN = sizeof(KEY) - 1;
#define TAG_LEN 32

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


void handle_authenticate(const struct pcap_pkthdr *header, const u_char *packet){ // take in packet
    unsigned char full_tag[EVP_MAX_MD_SIZE];
    unsigned int full_len = 0;

    // authenticate original packet bytes
    HMAC(EVP_sha256(), KEY, KEY_LEN, packet, header->len, full_tag, &full_len); // full_len will be 32

    // append to packet
    unsigned int new_len = header->len + TAG_LEN;
    unsigned char *out = malloc(new_len);
    if (!out) return;

    memcpy(out, packet, header->len);
    memcpy(out + header->len, full_tag, TAG_LEN);

    if (pcap_sendpacket(send_handle, out, new_len) != 0)
        fprintf(stderr, "send failed: %s\n", pcap_geterr(send_handle));

    free(out);
}

int handle_verify(const struct pcap_pkthdr *header, const u_char *packet){
    // take in packet
    unsigned char full_tag[EVP_MAX_MD_SIZE];
    unsigned int full_len = 0;
    int original_packet_len = header->len - TAG_LEN;
    const u_char *recv_tag = packet + original_packet_len;

    // authenticate the original packet bytes
    HMAC(EVP_sha256(), KEY, KEY_LEN, packet, original_packet_len, full_tag, &full_len); // full_len will be 32

    // compare the tags
    if (CRYPTO_memcmp(recv_tag, full_tag, TAG_LEN) != 0) {
        printf("packet not verified");
        return 0; // invalid
    }

    printf("packet verified successfully");

    if (pcap_sendpacket(send_handle, packet, original_packet_len) != 0)
        fprintf(stderr, "send failed: %s\n", pcap_geterr(send_handle));

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

    //configure capture handle
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

    //configure the send handle similar to capture handle
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