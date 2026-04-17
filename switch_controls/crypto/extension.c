#include "crypto/extension.h"
#include <string.h>

// handles the creation and the parsing of the extension field
// switch.c/h uses this

size_t ext_len(uint8_t tag_len, uint8_t nonce_len)
{
    // extension layout: profile_id + tag  + nonce
    return 1 + (size_t)tag_len + (size_t)nonce_len;
}

// takes existing frame and writes to out, the frame with the new authentication extension
size_t ext_append(uint8_t *out, size_t out_cap, const uint8_t *pkt, size_t pkt_len, uint8_t profile_id, const uint8_t *nonce, uint8_t nonce_len, const uint8_t *tag,   uint8_t tag_len) {
    size_t e = ext_len(tag_len, nonce_len); // how many bytes extension will take
    if (!out || !pkt) return 0;
    if (out_cap < pkt_len + e) return 0;

    memcpy(out, pkt, pkt_len); // copy original packet into the output buffer

    // sort and place values into extenion of form profile_id, tag, nonce
    size_t off = pkt_len;
    out[off++] = profile_id;

    if (tag_len) memcpy(out + off, tag, tag_len);
    off += tag_len;

    if (nonce_len) memcpy(out + off, nonce, nonce_len);
    off += nonce_len;

    return off; // return new length
}

// given received packet parses the extension from the enf o packet
int ext_parse_footer_fixed(const uint8_t *pkt, size_t pkt_len, uint8_t expected_profile_id, uint8_t expected_nonce_len, uint8_t expected_tag_len, const uint8_t **nonce_out,
                           const uint8_t **tag_out, size_t *original_len_out){
    if (!pkt || !nonce_out || !tag_out || !original_len_out) return 0;

    // if packet is shorter than the expected length then must be an error
    size_t e = ext_len(expected_tag_len, expected_nonce_len);
    if (pkt_len < e) return 0;

    // footer starts at packet len-e, then get values from the correct positions
    size_t start = pkt_len - e;
    size_t off = start;

    uint8_t pid = pkt[off++];
    if (pid != expected_profile_id) return 0;
    // functionality could be added to handle profile that dosent exist, but outwith this project scope

    const uint8_t *tag = pkt + off;
    off += expected_tag_len;

    const uint8_t *nonce = pkt + off;
    off += expected_nonce_len;

    // return pointers to the parsed nonce, tag and original packet length
    *tag_out = tag;
    *nonce_out = nonce;
    *original_len_out = start;
    return 1;
}
