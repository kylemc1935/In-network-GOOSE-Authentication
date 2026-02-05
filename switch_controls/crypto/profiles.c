#include "crypto/profiles.h"

/* One master key (make it at least 32 bytes to satisfy ChaCha20-Poly1305) */
static const uint8_t KEY[32] = {
    0x74,0x65,0x73,0x74,0x69,0x6e,0x67,0x6b,
    0x65,0x79,0x2d,0x6d,0x61,0x73,0x74,0x65,
    0x72,0x2d,0x6b,0x65,0x79,0x2d,0x33,0x32,
    0x2d,0x62,0x79,0x74,0x65,0x73,0x21,0x21
};

static const profile_t PROFILES[] = {
    // HMAC-SHA256 (auth only)
    { .profile_id=1, .mode=PROFILE_MODE_MAC,  .alg=ALG_HMAC_SHA256,
      .tag_len=32, .nonce_len=0,  .key=KEY, .key_len=32 },

    // BLAKE2s (auth only)
    { .profile_id=2, .mode=PROFILE_MODE_MAC,  .alg=ALG_BLAKE2S,
      .tag_len=32, .nonce_len=0,  .key=KEY, .key_len=32 },

    // AES-GCM (auth only)  16-byte AES key
    { .profile_id=3, .mode=PROFILE_MODE_MAC,  .alg=ALG_AES_GCM,
      .tag_len=16, .nonce_len=12, .key=KEY, .key_len=16 },

    // ChaCha20-Poly1305 (auth only) 32-byte key
    { .profile_id=4, .mode=PROFILE_MODE_MAC,  .alg=ALG_CHACHA20_POLY1305,
      .tag_len=16, .nonce_len=12, .key=KEY, .key_len=32 },

    // AES-GCM (AEAD)
    { .profile_id=5, .mode=PROFILE_MODE_AEAD, .alg=ALG_AES_GCM,
      .tag_len=16, .nonce_len=12, .key=KEY, .key_len=16 },

    // ChaCha20-Poly1305 (AEAD)
    { .profile_id=6, .mode=PROFILE_MODE_AEAD, .alg=ALG_CHACHA20_POLY1305,
      .tag_len=16, .nonce_len=12, .key=KEY, .key_len=32 },
};

static const size_t PROFILE_COUNT = sizeof(PROFILES)/sizeof(PROFILES[0]);

const profile_t* profile_lookup(uint8_t profile_id)
{
    for (size_t i = 0; i < PROFILE_COUNT; i++) {
        if (PROFILES[i].profile_id == profile_id) return &PROFILES[i];
    }
    return NULL;
}

const char *alg_to_str(crypto_alg_t alg) {
    switch (alg) {
        case ALG_HMAC_SHA256:   return "HMAC-SHA256";
        case ALG_BLAKE2S:       return "BLAKE2s-256";
        case ALG_AES_GCM:      return "AES-GMAC";
        case ALG_CHACHA20_POLY1305:   return "ChaCha20-Poly1305";
    }
}
