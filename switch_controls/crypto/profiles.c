#include <string.h>
#include <stdio.h>
#include "crypto/profiles.h"

// handles the cryptography profiles for the algorithm and associated data

/* One master key - random and long enough to suuport all algorithms */
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

// returns profile matching profile_id
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
        default:                      return "ALG?";
    }
}

// selcects the correct gcm function based on key length
static const EVP_CIPHER* pick_gcm_cipher(size_t key_len) {
    return (key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
}

// creates cryptographic profile, initalising the openssl contexts and data
int profile_crypto_init(profile_crypto_t *crypto, const profile_t *p)
{
    if (!crypto || !p) return 0;
    memset(crypto, 0, sizeof(*crypto));

    // pick algorithm primitives
    switch (p->alg) {
        case ALG_HMAC_SHA256:
            crypto->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
            if (!crypto->mac) return 0;

            crypto->hmac_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
            crypto->hmac_params[1] = OSSL_PARAM_construct_end();
            break;
        case ALG_BLAKE2S:
            crypto->mac = EVP_MAC_fetch(NULL, "BLAKE2SMAC", NULL);
            if (!crypto->mac) return 0;
            break;
        case ALG_AES_GCM:
            crypto->cipher = pick_gcm_cipher(p->key_len);
            if (!crypto->cipher) return 0;
            break;
        case ALG_CHACHA20_POLY1305:
            crypto->cipher = EVP_chacha20_poly1305();
            if (!crypto->cipher) return 0;
            break;
        default:
            return 0;
    }

    // allocate reusable cipher ctx’s if possible - not possible for MACs currentky
    if (p->alg == ALG_AES_GCM || p->alg == ALG_CHACHA20_POLY1305) {
        if (p->mode == PROFILE_MODE_MAC) {
            // MAC only uses the aead-auth only contexts also
            crypto->aead_ctx = EVP_CIPHER_CTX_new();
            if (!crypto->aead_ctx) goto fail;
        } else if (p->mode == PROFILE_MODE_AEAD) {
            // full AEAD requires seperate enc and dec and contexts
            crypto->aead_enc = EVP_CIPHER_CTX_new();
            crypto->aead_dec = EVP_CIPHER_CTX_new();
            if (!crypto->aead_enc || !crypto->aead_dec) goto fail;
        } else {
            goto fail;
        }
    }

    crypto->inited = 1;
    return 1;

fail:
    profile_crypto_cleanup(crypto);
    return 0;
}

//frees any openssl data
void profile_crypto_cleanup(profile_crypto_t *crypto)
{
    if (!crypto) return;

    if (crypto->aead_ctx) { EVP_CIPHER_CTX_free(crypto->aead_ctx); crypto->aead_ctx = NULL; }
    if (crypto->aead_enc) { EVP_CIPHER_CTX_free(crypto->aead_enc); crypto->aead_enc = NULL; }
    if (crypto->aead_dec) { EVP_CIPHER_CTX_free(crypto->aead_dec); crypto->aead_dec = NULL; }

    if (crypto->mac) { EVP_MAC_free(crypto->mac); crypto->mac = NULL; }

    crypto->cipher = NULL;
    crypto->inited = 0;
}



