#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <stdint.h>
#include "profiles.h"

// functions for the authentcation algorithms, for both the MAC and aead auth-only versions

// computes tag for auth only profiles
int auth_compute_tag(const profile_t *p, const profile_crypto_t *crypto, EVP_CIPHER_CTX *aead_ctx,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *nonce, size_t nonce_len,
                     uint8_t *out_tag, size_t out_tag_cap,
                     size_t *out_tag_len);

// verifies the authentication tag
// returns 1 is successful, and 0 if not
int auth_verify_tag(const profile_t *p, const profile_crypto_t *crypto, EVP_CIPHER_CTX *aead_ctx,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *recv_tag, size_t recv_tag_len);

#endif
