
#include "payload_crypto.h"

#include <stdint.h>
#include <string.h>

int encrypt_payload(
    const unsigned char key[AES_KEY_SIZE],
    NonceManager *manager,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_len
) {
    if (!key || !manager || !plaintext || !output || !output_len) {
        return 0;
    }

    *output_len = 0;

    if (plaintext_len > SIZE_MAX - PAYLOAD_OVERHEAD ||
        output_capacity < plaintext_len + PAYLOAD_OVERHEAD) {
        return 0;
    }

    unsigned char nonce[GCM_NONCE_SIZE];

    if (!nonce_manager_next(manager, nonce)) {
        return 0;
    }

    if (!aes_gcm_encrypt(
            key,
            nonce,
            plaintext,
            plaintext_len,
            output + GCM_NONCE_SIZE,
            output + GCM_NONCE_SIZE + plaintext_len)) {
        return 0;
    }

    memcpy(output, nonce, GCM_NONCE_SIZE);

    *output_len = plaintext_len + PAYLOAD_OVERHEAD;

    return 1;
}

int decrypt_payload(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char *input,
    size_t input_len,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
) {
    if (!key || !input || !plaintext || !plaintext_len) {
        return 0;
    }

    *plaintext_len = 0;

    if (input_len < PAYLOAD_OVERHEAD) {
        return 0;
    }

    size_t ciphertext_len = input_len - PAYLOAD_OVERHEAD;

    if (plaintext_capacity < ciphertext_len) {
        return 0;
    }

    const unsigned char *nonce = input;
    const unsigned char *ciphertext = input + GCM_NONCE_SIZE;
    const unsigned char *tag = ciphertext + ciphertext_len;

    if (!aes_gcm_decrypt(
            key,
            nonce,
            ciphertext,
            ciphertext_len,
            tag,
            plaintext)) {
        return 0;
    }

    *plaintext_len = ciphertext_len;

    return 1;
}
