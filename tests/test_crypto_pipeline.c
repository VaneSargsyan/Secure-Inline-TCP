
#include "payload_crypto.h"
#include "nonce_manager.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char key[AES_KEY_SIZE] = {0};
    unsigned char wrong_key[AES_KEY_SIZE] = {0};
    unsigned char prefix[4] = {1, 2, 3, 4};

    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = (unsigned char)(i + 1);
        wrong_key[i] = (unsigned char)(i + 2);
    }

    NonceManager manager = {0};

    assert(nonce_manager_init(&manager, prefix) == 1);

    const unsigned char plaintext[] =
        "Secure Inline TCP Encryption Test";

    size_t plaintext_len = sizeof(plaintext) - 1;

    unsigned char encrypted1[256] = {0};
    unsigned char encrypted2[256] = {0};
    unsigned char decrypted[256] = {0};

    size_t encrypted1_len = 0;
    size_t encrypted2_len = 0;
    size_t decrypted_len = 0;

    assert(encrypt_payload(
        key,
        &manager,
        plaintext,
        plaintext_len,
        encrypted1,
        sizeof(encrypted1),
        &encrypted1_len
    ) == 1);

    assert(encrypted1_len == plaintext_len + PAYLOAD_OVERHEAD);

    assert(decrypt_payload(
        key,
        encrypted1,
        encrypted1_len,
        decrypted,
        sizeof(decrypted),
        &decrypted_len
    ) == 1);

    assert(decrypted_len == plaintext_len);
    assert(memcmp(decrypted, plaintext, plaintext_len) == 0);

    printf("Encryption and decryption: PASSED\n");

    assert(encrypt_payload(
        key,
        &manager,
        plaintext,
        plaintext_len,
        encrypted2,
        sizeof(encrypted2),
        &encrypted2_len
    ) == 1);

    assert(encrypted2_len == encrypted1_len);
    assert(memcmp(encrypted1, encrypted2, encrypted1_len) != 0);
    assert(memcmp(
        encrypted1,
        encrypted2,
        GCM_NONCE_SIZE
    ) != 0);

    printf("Unique nonce and ciphertext: PASSED\n");

    unsigned char tampered[256] = {0};

    memcpy(tampered, encrypted1, encrypted1_len);
    tampered[GCM_NONCE_SIZE] ^= 0x01;

    decrypted_len = 0;

    assert(decrypt_payload(
        key,
        tampered,
        encrypted1_len,
        decrypted,
        sizeof(decrypted),
        &decrypted_len
    ) != 1);

    printf("Tampered ciphertext rejection: PASSED\n");

    memcpy(tampered, encrypted1, encrypted1_len);
    tampered[encrypted1_len - 1] ^= 0x01;

    decrypted_len = 0;

    assert(decrypt_payload(
        key,
        tampered,
        encrypted1_len,
        decrypted,
        sizeof(decrypted),
        &decrypted_len
    ) != 1);

    printf("Tampered authentication tag rejection: PASSED\n");

    decrypted_len = 0;

    assert(decrypt_payload(
        wrong_key,
        encrypted1,
        encrypted1_len,
        decrypted,
        sizeof(decrypted),
        &decrypted_len
    ) != 1);

    printf("Wrong key rejection: PASSED\n");

    decrypted_len = 0;

    assert(decrypt_payload(
        key,
        encrypted1,
        GCM_NONCE_SIZE + GCM_TAG_SIZE - 1,
        decrypted,
        sizeof(decrypted),
        &decrypted_len
    ) != 1);

    printf("Invalid payload length rejection: PASSED\n");

    printf("All crypto pipeline tests passed\n");

    return 0;
}
