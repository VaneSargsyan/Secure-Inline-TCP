
#include "aes_gcm.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

int aes_gcm_encrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char nonce[GCM_NONCE_SIZE],
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char tag[GCM_TAG_SIZE]
) {
    if (!key || !nonce || !plaintext || !ciphertext || !tag ||
        plaintext_len > INT_MAX) {
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0;
    int final_len = 0;
    int success = 0;

    if (EVP_EncryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(
            ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(
            ctx, ciphertext, &len,
            plaintext, (int)plaintext_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(
            ctx, ciphertext + len, &final_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1)
        goto cleanup;

    success = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

int aes_gcm_decrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char nonce[GCM_NONCE_SIZE],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[GCM_TAG_SIZE],
    unsigned char *plaintext
) {
    if (!key || !nonce || !ciphertext || !tag || !plaintext ||
        ciphertext_len > INT_MAX) {
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int len = 0;
    int final_len = 0;
    int success = 0;

    if (EVP_DecryptInit_ex(
            ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(
            ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(
            ctx, plaintext, &len,
            ciphertext, (int)ciphertext_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_SIZE, (void *)tag) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(
            ctx, plaintext + len, &final_len) != 1)
        goto cleanup;

    success = 1;

cleanup:
    if (!success && ciphertext_len > 0) {
        OPENSSL_cleanse(plaintext, ciphertext_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    return success;
}
