#include "crypto/auth.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

// from openSSL pages - out -> output buffer
//                    - outlen -> is the bytes actually written
//                    - outsize -> is the capacity that the out can actually hold (used out cap here as harder to get mixed up)

// HMAC-SHA256
static int hmac_sha256(const profile_t *p, const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out, size_t out_cap, size_t *out_len){
    if (out_cap < 32) return 0; // ensure it can hold the 32 byte output

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL); // load hmac
    if (!mac) return 0;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac); // create mac context
    if (!ctx) { EVP_MAC_free(mac); return 0; }

    //
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    size_t len = 0; // len receives the output length and ok is succes flag
    int ok = 0;

    // initalise and use nonce to form message bytes and write the MAC
    if (EVP_MAC_init(ctx, p->key, p->key_len, params) != 1) goto done;
    if (nonce && nonce_len) if (EVP_MAC_update(ctx, nonce, nonce_len) != 1) goto done; // nonce not used here but kept in if needed
    if (EVP_MAC_update(ctx, msg, msg_len) != 1) goto done;
    if (EVP_MAC_final(ctx, out, &len, out_cap) != 1) goto done;

    *out_len = len; // should be 32
    ok = 1;

done:  // cleanup
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

static int blake2s_keyed(const profile_t *p, const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out, size_t out_cap, size_t *out_len){
    if (!p || !p->key || p->key_len == 0) return 0;
    if (out_cap < 32) return 0;

    int ok = 0;
    size_t len = 0;

    // fetch BLAKE2SMAC not BLAKE2S
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "BLAKE2SMAC", NULL);
    if (!mac) {
        fprintf(stderr, "EVP_MAC_fetch(BLAKE2SMAC) failed\n");
        return 0;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac); //create context
    if (!ctx) { EVP_MAC_free(mac); return 0; }

    // intalise and use nonce to form message and output the mac
    if (EVP_MAC_init(ctx, p->key, p->key_len, NULL) != 1) goto done;
    if (nonce && nonce_len) if (EVP_MAC_update(ctx, nonce, nonce_len) != 1) goto done; // nonce not used here but kept in if needed
    if (EVP_MAC_update(ctx, msg, msg_len) != 1) goto done;
    if (EVP_MAC_final(ctx, out, &len, out_cap) != 1) goto done;

    *out_len = len;
    ok = 1;

done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}



// helper functon for cho0sing gcm key size
static const EVP_CIPHER* pick_gcm_cipher(size_t key_len) {
    return (key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
}

static int gmac_auth_only(const profile_t *p, const uint8_t *aad, size_t aad_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out, size_t out_cap, size_t *out_len){
    if (out_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;

    int ok = 0; // temporary and success flag
    int tmp = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // create context
    if (!ctx) return 0;

    const EVP_CIPHER *cipher = pick_gcm_cipher(p->key_len); // select alg based on key length

    // initalie the context, set the nonce length and then feed the mesage into GCM
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;
    if (aad && aad_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &tmp, aad, (int)aad_len) != 1) goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, NULL, &tmp) != 1) goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out) != 1) goto done; // extract the tag

    *out_len = 16;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int chacha_poly_auth_only(const profile_t *p, const uint8_t *aad, size_t aad_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out, size_t out_cap, size_t *out_len){
    if (out_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;
    // similar to the gcm setup - could maybe combine into one function? not sure if worth it for now
    int ok = 0;
    int tmp = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &tmp, aad, (int)aad_len) != 1) goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, NULL, &tmp) != 1) goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out) != 1) goto done;

    *out_len = 16;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}



int auth_compute_tag(const profile_t *profile, const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len){
    if (!profile || !msg || !out_tag || !out_tag_len) return 0;
    if (out_tag_cap < profile->tag_len) return 0; // biffer must be big enough

    size_t produced = 0; // how many bytes the chosen alg produces
    int ok = 0; // success flag

    // switch based on chosen alg and perform authentication
    switch (profile->alg) {
        case ALG_HMAC_SHA256:
            ok = hmac_sha256(profile, msg, msg_len, nonce, nonce_len, out_tag, out_tag_cap, &produced);
            break;
        case ALG_BLAKE2S:
            ok = blake2s_keyed(profile, msg, msg_len, nonce, nonce_len, out_tag, out_tag_cap, &produced);
            break;
        case ALG_AES_GCM:
            ok = gmac_auth_only(profile, msg, msg_len, nonce, nonce_len, out_tag, out_tag_cap, &produced);
            break;
        case ALG_CHACHA20_POLY1305:
            ok = chacha_poly_auth_only(profile, msg, msg_len, nonce, nonce_len, out_tag, out_tag_cap, &produced);
            break;
        default:
            return 0;
    }

    if (!ok) return 0;
    if (produced != profile->tag_len) return 0; // alg must produce exactly what the profile expects else an error

    *out_tag_len = produced;
    return 1; // return produces tag length and signal success
}

int auth_verify_tag(const profile_t *p, const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *recv_tag, size_t recv_tag_len){
    if (!p || !msg || !recv_tag) return 0;
    if (recv_tag_len != p->tag_len) return 0;

    uint8_t calc[64]; // local buffer for the computed tag
    size_t calc_len = 0;

    // uses the above function to recompute the tag and then returns the result of comparing it to the transmitted tag
    if (!auth_compute_tag(p, msg, msg_len, nonce, nonce_len, calc, sizeof(calc), &calc_len))
        return 0;

    return CRYPTO_memcmp(calc, recv_tag, recv_tag_len) == 0;
}
