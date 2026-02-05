#include "crypto/aead.h"

#include <openssl/evp.h>
#include <string.h>

static const EVP_CIPHER* pick_gcm_cipher(size_t key_len) {
    return (key_len == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
}

// aed-gcm aead
static int aes_gcm_encrypt_inplace(const profile_t *p, const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                   uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len){

    if (out_tag_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // create cipher context
    if (!ctx) return 0;

    int ok = 0, outl = 0; // return flag and output param (length)
    const EVP_CIPHER *cipher = pick_gcm_cipher(p->key_len); // select correct function based on key len

    // setup context with cipher and set the nonce and key
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) { // add aad if required
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (buf_len) { // encrypt the plaintext in buf into ciphertext
        if (EVP_EncryptUpdate(ctx, buf, &outl, buf, (int)buf_len) != 1) goto done;
    }

    //  finalise encryption and pull the tag out of context
    if (EVP_EncryptFinal_ex(ctx, buf + outl, &outl) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_tag) != 1) goto done;

    *out_tag_len = 16;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes_gcm_decrypt_verify_inplace(const profile_t *p, const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                          const uint8_t *recv_tag, size_t recv_tag_len){
    if (recv_tag_len != 16) return 0;
    if (!nonce || nonce_len == 0) return 0;

    // same as encryption but decrypt .....
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 0, outl = 0;

    const EVP_CIPHER *cipher = pick_gcm_cipher(p->key_len);

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (buf_len) {
        if (EVP_DecryptUpdate(ctx, buf, &outl, buf, (int)buf_len) != 1) goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)recv_tag) != 1) goto done;

    ok = (EVP_DecryptFinal_ex(ctx, buf + outl, &outl) == 1); // result of if tag passes of not

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// chacha20-poly1306 aead
static int chacha_poly_encrypt_inplace(const profile_t *p, const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                       uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len){
    if (out_tag_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // create cipher context
    if (!ctx) return 0;

    int ok = 0, outl = 0;

    // setup context with nonce and key
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) { // aad if needed
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (buf_len) {
        if (EVP_EncryptUpdate(ctx, buf, &outl, buf, (int)buf_len) != 1) goto done;
    }

    // finalise encryption and get tag
    if (EVP_EncryptFinal_ex(ctx, buf + outl, &outl) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out_tag) != 1) goto done;

    *out_tag_len = 16;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int chacha_poly_decrypt_verify_inplace(const profile_t *p, const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                              const uint8_t *recv_tag, size_t recv_tag_len){
    if (recv_tag_len != 16) return 0;
    if (!nonce || nonce_len == 0) return 0;

    // similar to encrypt version but for decrypting and verifying
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 0, outl = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (buf_len) {
        if (EVP_DecryptUpdate(ctx, buf, &outl, buf, (int)buf_len) != 1) goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)recv_tag) != 1) goto done;

    ok = (EVP_DecryptFinal_ex(ctx, buf + outl, &outl) == 1);

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// public api wrappers
int aead_encrypt_inplace(const profile_t *p, const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                         uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len){
    if (!p || !buf || !out_tag || !out_tag_len) return 0;
    if (p->mode != PROFILE_MODE_AEAD) return 0;
    if (out_tag_cap < p->tag_len) return 0;

    switch (p->alg) {
        case ALG_AES_GCM:
            return aes_gcm_encrypt_inplace(p, aad, aad_len, buf, buf_len, nonce, nonce_len,
                                           out_tag, out_tag_cap, out_tag_len);
        case ALG_CHACHA20_POLY1305:
            return chacha_poly_encrypt_inplace(p, aad, aad_len, buf, buf_len, nonce, nonce_len,
                                               out_tag, out_tag_cap, out_tag_len);
        default:
            return 0;
    }
}

int aead_decrypt_verify_inplace(const profile_t *p, const uint8_t *aad, size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *recv_tag, size_t recv_tag_len){
    if (!p || !buf || !recv_tag) return 0;
    if (p->mode != PROFILE_MODE_AEAD) return 0;
    if (recv_tag_len != p->tag_len) return 0;

    switch (p->alg) {
        case ALG_AES_GCM:
            return aes_gcm_decrypt_verify_inplace(p, aad, aad_len, buf, buf_len, nonce, nonce_len, recv_tag, recv_tag_len);
        case ALG_CHACHA20_POLY1305:
            return chacha_poly_decrypt_verify_inplace(p, aad, aad_len, buf, buf_len, nonce, nonce_len, recv_tag, recv_tag_len);
        default:
            return 0;
    }
}
