
#ifndef PAYLOAD_CRYPTO_H
#define PAYLOAD_CRYPTO_H

#include <stddef.h>
#include "aes_gcm.h"
#include "nonce_manager.h"

#define PAYLOAD_OVERHEAD (GCM_NONCE_SIZE + GCM_TAG_SIZE)

int encrypt_payload(
    const unsigned char key[AES_KEY_SIZE],
    NonceManager *manager,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_len
);

int decrypt_payload(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char *input,
    size_t input_len,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
);

#endif
