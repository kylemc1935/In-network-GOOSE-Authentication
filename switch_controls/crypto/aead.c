#include "crypto/aead.h"
#include <openssl/evp.h>
#include <string.h>

// AEAD functions for the GOOSE encryption and authentication, and decryption

// now adjusted to take the crytpo struct for the initalized ciphers and contexts to save per packet computations
// aed-gcm aead
// buf (packet) is encrypted in place and writes authentication tag into out_tag, AAD is provided by the caller (ethernet frame in this case)
static int aes_gcm_encrypt_inplace(const profile_t *p, profile_crypto_t *crypto, const uint8_t *aad, size_t aad_len,
                                   uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                   uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len)
{
    if (out_tag_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;
    if (!crypto || !crypto->aead_enc || !crypto->cipher) return 0;

    EVP_CIPHER_CTX *ctx = crypto->aead_enc;

    int ok = 0, outl = 0;

    //  clear any previous state before reinitalising for new packet
    EVP_CIPHER_CTX_reset(ctx);

    // setup context with cipher and set the nonce and key
    if (EVP_EncryptInit_ex(ctx, crypto->cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) { // add aad to computation if defined
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
    return ok;
}

// similarly decrypts buf in place and verifies the transmitted authentication tag
static int aes_gcm_decrypt_verify_inplace(const profile_t *p, profile_crypto_t *crypto, const uint8_t *aad, size_t aad_len,
                                          uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                          const uint8_t *recv_tag, size_t recv_tag_len)
{
    if (recv_tag_len != 16) return 0;
    if (!nonce || nonce_len == 0) return 0;
    if (!crypto || !crypto->aead_dec || !crypto->cipher) return 0;

    // same as encryption but decrypt .....
    EVP_CIPHER_CTX *ctx = crypto->aead_dec;

    int ok = 0, outl = 0;

    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_DecryptInit_ex(ctx, crypto->cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, p->key, nonce) != 1) goto done;

    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (buf_len) {
        if (EVP_DecryptUpdate(ctx, buf, &outl, buf, (int)buf_len) != 1) goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)recv_tag) != 1) goto done;

    // verify tag, and return the output
    ok = (EVP_DecryptFinal_ex(ctx, buf + outl, &outl) == 1);

done:
    return ok;
}

// chacha20-poly1306 aead, same as the aes-gmac functions
static int chacha_poly_encrypt_inplace(const profile_t *p, profile_crypto_t *crypto, const uint8_t *aad, size_t aad_len,
                                       uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                       uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len)
{
    if (out_tag_cap < 16) return 0;
    if (!nonce || nonce_len == 0) return 0;
    if (!crypto || !crypto->aead_enc || !crypto->cipher) return 0;

    EVP_CIPHER_CTX *ctx = crypto->aead_enc;
    int ok = 0, outl = 0;

    EVP_CIPHER_CTX_reset(ctx);

    // setup context with nonce and key
    if (EVP_EncryptInit_ex(ctx, crypto->cipher, NULL, NULL, NULL) != 1) goto done;
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
    return ok;
}
// chacha20-poly1305 decrypt, same as the aes-gmac functions
static int chacha_poly_decrypt_verify_inplace(const profile_t *p, profile_crypto_t *crypto, const uint8_t *aad, size_t aad_len,
                                              uint8_t *buf, size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                              const uint8_t *recv_tag, size_t recv_tag_len){
    if (recv_tag_len != 16) return 0;
    if (!nonce || nonce_len == 0) return 0;
    if (!crypto || !crypto->aead_dec || !crypto->cipher) return 0;

    // similar to encrypt version but for decrypting and verifying
    EVP_CIPHER_CTX *ctx = crypto->aead_dec;
    if (!ctx) return 0;

    int ok = 0, outl = 0;

    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_DecryptInit_ex(ctx, crypto->cipher, NULL, NULL, NULL) != 1) goto done;
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
    return ok;
}

// public api wrappers for aead encryption
int aead_encrypt_inplace(const profile_t *p, profile_crypto_t *crypto, const uint8_t *aad, size_t aad_len, uint8_t *buf,
                         size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                         uint8_t *out_tag, size_t out_tag_cap, size_t *out_tag_len){
    if (!p || !buf || !out_tag || !out_tag_len) return 0;
    if (p->mode != PROFILE_MODE_AEAD) return 0;
    if (out_tag_cap < p->tag_len) return 0;

    switch (p->alg) {
        case ALG_AES_GCM:
            return aes_gcm_encrypt_inplace(p, crypto, aad, aad_len, buf, buf_len, nonce, nonce_len,
                                           out_tag, out_tag_cap, out_tag_len);
        case ALG_CHACHA20_POLY1305:
            return chacha_poly_encrypt_inplace(p, crypto, aad, aad_len, buf, buf_len, nonce, nonce_len,
                                               out_tag, out_tag_cap, out_tag_len);
        default:
            return 0;
    }
}

// similar for the aead decrypt
int aead_decrypt_verify_inplace(const profile_t *p, profile_crypto_t *crypto, const uint8_t *aad, size_t aad_len, uint8_t *buf,
                                size_t buf_len, const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *recv_tag, size_t recv_tag_len){
    if (!p || !buf || !recv_tag) return 0;
    if (p->mode != PROFILE_MODE_AEAD) return 0;
    if (recv_tag_len != p->tag_len) return 0;

    switch (p->alg) {
        case ALG_AES_GCM:
            return aes_gcm_decrypt_verify_inplace(p, crypto, aad, aad_len, buf, buf_len, nonce, nonce_len, recv_tag, recv_tag_len);
        case ALG_CHACHA20_POLY1305:
            return chacha_poly_decrypt_verify_inplace(p, crypto, aad, aad_len, buf, buf_len, nonce, nonce_len, recv_tag, recv_tag_len);
        default:
            return 0;
    }
}
