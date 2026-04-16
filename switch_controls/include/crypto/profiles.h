#ifndef PROFILES_H
#define PROFILES_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

// profile mode defines the profile used
typedef enum {
    PROFILE_MODE_MAC  = 1,   // authen only (no payload encryption)
    PROFILE_MODE_AEAD = 2    // encrypt + authenticate
} profile_mode_t;

// this defines the supported cryptogrphic algorithms, gcm and chacha, have both working profile modes for this
typedef enum {
    ALG_HMAC_SHA256 = 1,     // MAC
    ALG_BLAKE2S    = 2,     // MAC
    ALG_AES_GCM     = 3,     // MAC only or AEAD
    ALG_CHACHA20_POLY1305 = 4 // MAC only or AEAD
} crypto_alg_t;

// profile definition for the cryptographic profile
typedef struct {
    uint8_t        profile_id; // profile identifier
    profile_mode_t mode; // AEAD or auth only
    crypto_alg_t   alg; // alg

    uint8_t        tag_len; // authentication tag length in bytes
    uint8_t        nonce_len; // nonce len used in bytes

    const uint8_t *key;  // pointer to the key
    size_t         key_len; // key length used in bytes
} profile_t;

// runtime cryptographic state used, to store reusable contexts, to
// avoid per packet initialisation
typedef struct {
    int inited;

    // MAC-based algorithm states: HMAC, BLAKE
    EVP_MAC *mac; // mac
    OSSL_PARAM hmac_params[2];    //param list: digest=SHA256, end

    // AEAD-based algorithm states: GMAC, ChaCha
    const EVP_CIPHER *cipher; // cipher and resuable aead context for auth-only and aead
    EVP_CIPHER_CTX *aead_ctx;
    // needed for AEAD encryption/decryption
    EVP_CIPHER_CTX *aead_enc;
    EVP_CIPHER_CTX *aead_dec;
} profile_crypto_t;

// initalises the openssl state required for the given profile
int profile_crypto_init(profile_crypto_t *crypto, const profile_t *p);
// similar cleanup function, to release any openssl state
void profile_crypto_cleanup(profile_crypto_t *crypto);

// looks up cryptography profile to get a pointer to matching profile
// accessing the associated dta
const profile_t* profile_lookup(uint8_t profile_id);
// returns alg as string
const char *alg_to_str(crypto_alg_t alg);

#endif