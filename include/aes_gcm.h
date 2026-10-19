#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>

#define AES_KEY_SIZE 32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

int aes_gcm_encrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char nonce[GCM_NONCE_SIZE],
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char tag[GCM_TAG_SIZE]
);

int aes_gcm_decrypt(
    const unsigned char key[AES_KEY_SIZE],
    const unsigned char nonce[GCM_NONCE_SIZE],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[GCM_TAG_SIZE],
    unsigned char *plaintext
);

#endif
