#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "profiles.h"

// encrypts buffer in place and outputs tag, aad (additional authen data) not used but kept in
int aead_encrypt_inplace(const profile_t *p,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *buf, size_t buf_len,
                         const uint8_t *nonce, size_t nonce_len,
                         uint8_t *out_tag, size_t out_tag_cap,
                         size_t *out_tag_len);

// decrypts buffer in place and verifies tag
int aead_decrypt_verify_inplace(const profile_t *p,
                                const uint8_t *aad, size_t aad_len,
                                uint8_t *buf, size_t buf_len,
                                const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *recv_tag, size_t recv_tag_len);

#endif
