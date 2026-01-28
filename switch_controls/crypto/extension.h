#ifndef EXT_H
#define EXT_H

#include <stddef.h>
#include <stdint.h>

// footer format (placed at end of frame) [ profile_id ][ nonce_len ][ nonce ][ tag_len ][ tag ]
// switch is in a predefined profile mode, so it expects exact lengths

size_t ext_len(uint8_t nonce_len, uint8_t tag_len);

// append extension to packet out must have capacity pkt_len + ext_len(nonce_len, tag_len)
// returns new length or 0 if error
size_t ext_append(uint8_t *out, size_t out_cap,
                  const uint8_t *pkt, size_t pkt_len,
                  uint8_t profile_id,
                  const uint8_t *nonce, uint8_t nonce_len,
                  const uint8_t *tag,   uint8_t tag_len);

// parse footer assuming predefined expected lengths
// returns 1 on success and sets pointers into pkt
int ext_parse_footer_fixed(const uint8_t *pkt, size_t pkt_len,
                           uint8_t expected_profile_id,
                           uint8_t expected_nonce_len,
                           uint8_t expected_tag_len,
                           const uint8_t **nonce_out,
                           const uint8_t **tag_out,
                           size_t *original_len_out);

#endif
