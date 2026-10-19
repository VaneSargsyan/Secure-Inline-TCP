
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "payload_crypto.h"

int main(void) {
    unsigned char key[AES_KEY_SIZE];
    unsigned char prefix[4];
    NonceManager manager;

    const unsigned char message[] = "Hello from PC1 to PC2!";
    unsigned char encrypted[sizeof(message) + PAYLOAD_OVERHEAD];
    unsigned char decrypted[sizeof(message)];
    size_t encrypted_len = 0;
    size_t decrypted_len = 0;

    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(prefix, sizeof(prefix)) != 1) {
        return 1;
    }

    if (!nonce_manager_init(&manager, prefix)) {
        return 1;
    }

    if (!encrypt_payload(
            key, &manager, message, sizeof(message),
            encrypted, sizeof(encrypted), &encrypted_len)) {
        return 1;
    }

    printf("SUCCESS: Payload encrypted!\n");

    if (!decrypt_payload(
            key, encrypted, encrypted_len,
            decrypted, sizeof(decrypted), &decrypted_len)) {
        return 1;
    }

    if (decrypted_len != sizeof(message) ||
        memcmp(message, decrypted, sizeof(message)) != 0) {
        return 1;
    }

    printf("SUCCESS: Payload decrypted correctly!\n");

    encrypted[encrypted_len - 1] ^= 1;

    if (decrypt_payload(
            key, encrypted, encrypted_len,
            decrypted, sizeof(decrypted), &decrypted_len)) {
        fprintf(stderr, "ERROR: Modified payload accepted!\n");
        return 1;
    }

    printf("SUCCESS: Modified payload rejected!\n");

    return 0;
}
