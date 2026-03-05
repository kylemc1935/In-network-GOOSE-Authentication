#include "crypto/auth.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

// wrapper for both hmac and blake
static int mac_authenticate(const profile_t *p, const profile_crypto_t *crypto,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *nonce, size_t nonce_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
                              {
    if (!p || !crypto || !crypto->mac || !out || !out_len) return 0;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(crypto->mac); // create mac context
    if (!ctx) return 0;

    size_t len = 0; // len receives the output length and ok is succes flag
    int ok = 0;

    const OSSL_PARAM *params = NULL;
    if (p->alg == ALG_HMAC_SHA256) params = crypto->hmac_params;

    // initalise and use nonce to form message bytes and write the MAC
    if (EVP_MAC_init(ctx, p->key, p->key_len, params) != 1) goto done;
    if (nonce && nonce_len) if (EVP_MAC_update(ctx, nonce, nonce_len) != 1) goto done; // nonce not used here but kept in if needed
    if (EVP_MAC_update(ctx, msg, msg_len) != 1) goto done;
    if (EVP_MAC_final(ctx, out, &len, out_cap) != 1) goto done;

    *out_len = len;
    ok = 1;

done:
    EVP_MAC_CTX_free(ctx);
    return ok;
}


// funct for both chacha and gcm in auth mody
// adjusted to use the same path as aead does in attempt to reduce latency
static int aead_auth_only(const profile_t *p, const profile_crypto_t *crypto, EVP_CIPHER_CTX *ctx, int is_gcm,
                                 const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len,
                                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!p || !crypto || !crypto->cipher || !ctx) return 0;
    if (out_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;

    int ok = 0; // temporary and success flag
    int tmp = 0;

    uint8_t discard[2048]; // this is for the ciphertext produced
    EVP_CIPHER_CTX_reset(ctx); // reuse ctx instead of new/free per packet

    // initalie the context, set the nonce length and then feed the mesage into GCM
    if (EVP_EncryptInit_ex(ctx, crypto->cipher, NULL, NULL, NULL) != 1) goto done;
    // set nonce len depending on the alg
    if (is_gcm) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    } else {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;
    if (msg && msg_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &tmp, msg, (int)msg_len) != 1) goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, discard + tmp, &tmp) != 1) goto done;

    // extract the tag
    if (is_gcm) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out) != 1) goto done;
    } else {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out) != 1) goto done;
    }

    *out_len = 16;
    ok = 1;

done:
    return ok;
}

int auth_compute_tag(const profile_t *profile, const profile_crypto_t *crypto, EVP_CIPHER_CTX *aead_ctx,
    const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len){
    if (!profile || !msg || !out_tag || !out_tag_len) return 0;
    if (out_tag_cap < profile->tag_len) return 0; // biffer must be big enough

    size_t produced = 0; // how many bytes the chosen alg produces
    int ok = 0; // success flag

    // switch based on chosen alg and perform authentication
    switch (profile->alg) {
        case ALG_HMAC_SHA256:
        case ALG_BLAKE2S:
            ok = mac_authenticate(profile, crypto, msg, msg_len, nonce, nonce_len,
                            out_tag, out_tag_cap, &produced);
            break;
        case ALG_AES_GCM:
            ok = aead_auth_only(profile, crypto, aead_ctx, 1, msg, msg_len, nonce, nonce_len,
                                       out_tag, out_tag_cap, &produced);
            break;
        case ALG_CHACHA20_POLY1305:
            ok = aead_auth_only(profile, crypto, aead_ctx, 0, msg, msg_len, nonce, nonce_len,
                                       out_tag, out_tag_cap, &produced);
            break;
        default:
            return 0;
    }

    if (!ok) return 0;
    if (produced != profile->tag_len) return 0; // alg must produce exactly what the profile expects else an error

    *out_tag_len = produced;
    return 1; // return produces tag length and signal success
}

int auth_verify_tag(const profile_t *p, const profile_crypto_t *crypto, EVP_CIPHER_CTX *aead_ctx,
    const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *recv_tag, size_t recv_tag_len){
    if (!p || !msg || !recv_tag) return 0;
    if (recv_tag_len != p->tag_len) return 0;

    uint8_t calc[64]; // local buffer for the computed tag
    size_t calc_len = 0;

    // uses the above function to recompute the tag and then returns the result of comparing it to the transmitted tag
    if (!auth_compute_tag(p, crypto, aead_ctx, msg, msg_len, nonce, nonce_len, calc, sizeof(calc), &calc_len))
        return 0;

    return CRYPTO_memcmp(calc, recv_tag, recv_tag_len) == 0;
}
