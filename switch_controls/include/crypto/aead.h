#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "profiles.h"

// AEAD functions for the GOOSE encryption and authentication, and decryption

// encrypts buffer in place and outputs tag, aad (additional authen data) not encrypted but authenticated
// writes the generated tag to out_tag and stores its length in out_tag_len
// returns 1 - success, 0 - error
int aead_encrypt_inplace(const profile_t *p, profile_crypto_t *crypto,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *buf, size_t buf_len,
                         const uint8_t *nonce, size_t nonce_len,
                         uint8_t *out_tag, size_t out_tag_cap,
                         size_t *out_tag_len);

// decrypts buffer in place and verifies the transmitted authentication tag
// returns 1 is verification is successful
int aead_decrypt_verify_inplace(const profile_t *p, profile_crypto_t *crypto,
                                const uint8_t *aad, size_t aad_len,
                                uint8_t *buf, size_t buf_len,
                                const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *recv_tag, size_t recv_tag_len);

#endif
