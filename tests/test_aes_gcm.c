
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "aes_gcm.h"

int main(void) {
    unsigned char key[AES_KEY_SIZE];
    unsigned char nonce[GCM_NONCE_SIZE];
    const unsigned char message[] = "Hello from PC1!";

    unsigned char ciphertext[sizeof(message)];
    unsigned char decrypted[sizeof(message)];
    unsigned char tag[GCM_TAG_SIZE];

    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Random generation failed!\n");
        return 1;
    }

    if (!aes_gcm_encrypt(
            key, nonce,
            message, sizeof(message),
            ciphertext, tag)) {
        fprintf(stderr, "Encryption failed!\n");
        return 1;
    }

    printf("SUCCESS: Encryption completed!\n");

    if (!aes_gcm_decrypt(
            key, nonce,
            ciphertext, sizeof(ciphertext),
            tag, decrypted)) {
        fprintf(stderr, "Decryption failed!\n");
        return 1;
    }

    if (CRYPTO_memcmp(message, decrypted, sizeof(message)) != 0) {
        fprintf(stderr, "Plaintext mismatch!\n");
        return 1;
    }

    printf("SUCCESS: Decrypted plaintext matches!\n");

    tag[0] ^= 1;

    if (aes_gcm_decrypt(
            key, nonce,
            ciphertext, sizeof(ciphertext),
            tag, decrypted)) {
        fprintf(stderr, "ERROR: Invalid tag accepted!\n");
        return 1;
    }

    printf("SUCCESS: Invalid authentication tag rejected!\n");

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(decrypted, sizeof(decrypted));

    return 0;
}
