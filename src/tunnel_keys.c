
#include "tunnel_keys.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

static int derive_key(
    const unsigned char session_key[SESSION_KEY_SIZE],
    const char *label,
    unsigned char output[TUNNEL_KEY_SIZE]
) {
    int success = 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (!ctx) {
        return 0;
    }

    size_t output_length = TUNNEL_KEY_SIZE;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(
            ctx, session_key, SESSION_KEY_SIZE
        ) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx, (const unsigned char *)label, (int)strlen(label)
        ) <= 0 ||
        EVP_PKEY_derive(ctx, output, &output_length) <= 0 ||
        output_length != TUNNEL_KEY_SIZE) {
        goto cleanup;
    }

    success = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return success;
}

int derive_tunnel_keys(
    const unsigned char session_key[SESSION_KEY_SIZE],
    unsigned char device1_to_device2[TUNNEL_KEY_SIZE],
    unsigned char device2_to_device1[TUNNEL_KEY_SIZE]
) {
    if (!derive_key(
            session_key,
            "Secure-Inline-TCP Device1 to Device2 v1",
            device1_to_device2)) {
        return 0;
    }

    if (!derive_key(
            session_key,
            "Secure-Inline-TCP Device2 to Device1 v1",
            device2_to_device1)) {
        return 0;
    }

    return 1;
}
