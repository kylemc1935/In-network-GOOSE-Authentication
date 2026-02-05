#ifndef PROFILES_H
#define PROFILES_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PROFILE_MODE_MAC  = 1,   // authen only (no payload encryption)
    PROFILE_MODE_AEAD = 2    // encrypt + authenticate
} profile_mode_t;

typedef enum {
    ALG_HMAC_SHA256 = 1,     // MAC
    ALG_BLAKE2S    = 2,     // MAC
    ALG_AES_GCM     = 3,     // MAC only or AEAD
    ALG_CHACHA20_POLY1305 = 4 // MAC only or AEAD
} crypto_alg_t;

typedef struct {
    uint8_t        profile_id;
    profile_mode_t mode; // AEAD or auth only
    crypto_alg_t   alg;

    uint8_t        tag_len;
    uint8_t        nonce_len;

    const uint8_t *key;
    size_t         key_len;
} profile_t;

const profile_t* profile_lookup(uint8_t profile_id);

const char *alg_to_str(crypto_alg_t alg);

#endif