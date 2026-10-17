#include "crypto_utils.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <limits.h>

int derive_session_key(
    const unsigned char *shared_secret,
    size_t secret_len,
    const unsigned char *salt,
    size_t salt_len,
    unsigned char session_key[SESSION_KEY_SIZE]
) {
    if (!shared_secret || secret_len == 0 ||
        !salt || salt_len == 0 || !session_key) {
        return 0;
    }

    int success = 0;

    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (!ctx) {
        return 0;
    }

    size_t key_len = SESSION_KEY_SIZE;

    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(
            ctx, EVP_sha256()) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_salt(
            ctx, salt, salt_len) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_key(
            ctx, shared_secret, secret_len) <= 0)
        goto cleanup;

    const unsigned char info[] =
        "Secure-Inline-TCP AES-256-GCM v1";

    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx, info, sizeof(info) - 1) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive(
            ctx, session_key, &key_len) <= 0)
        goto cleanup;

    success = (key_len == SESSION_KEY_SIZE);

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return success;
}

int compute_hmac(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *data,
    size_t data_len,
    unsigned char output[HMAC_SIZE]
) {
    if (!key || !data || !output ||
        key_len > INT_MAX) {
        return 0;
    }

    unsigned int output_len = 0;

    unsigned char *result = HMAC(
        EVP_sha256(),
        key,
        (int)key_len,
        data,
        data_len,
        output,
        &output_len
    );

    return result != NULL && output_len == HMAC_SIZE;
}
int derive_confirmation_key(
    const unsigned char *shared_secret,
    size_t secret_len,
    const unsigned char *salt,
    size_t salt_len,
    unsigned char confirmation_key[CONFIRM_KEY_SIZE]
) {
    if (!shared_secret || secret_len == 0 ||
        !salt || salt_len == 0 || !confirmation_key) {
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (!ctx) {
        return 0;
    }

    int success = 0;
    size_t key_len = CONFIRM_KEY_SIZE;

    const unsigned char info[] =
        "Secure-Inline-TCP key-confirmation v1";

    if (EVP_PKEY_derive_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_key(
            ctx, shared_secret, secret_len) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx, info, sizeof(info) - 1) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive(
            ctx, confirmation_key, &key_len) <= 0)
        goto cleanup;

    success = (key_len == CONFIRM_KEY_SIZE);

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return success;
}
