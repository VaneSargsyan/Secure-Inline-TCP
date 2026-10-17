#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

int main(void) {
    const unsigned char key[] = "test-key";
    const unsigned char data[] = "Device1-Device2";

    unsigned char hmac1[HMAC_SIZE];
    unsigned char hmac2[HMAC_SIZE];

    if (!compute_hmac(
            key, sizeof(key) - 1,
            data, sizeof(data) - 1,
            hmac1)) {
        fprintf(stderr, "HMAC 1 failed!\n");
        return 1;
    }

    if (!compute_hmac(
            key, sizeof(key) - 1,
            data, sizeof(data) - 1,
            hmac2)) {
        fprintf(stderr, "HMAC 2 failed!\n");
        return 1;
    }

    if (CRYPTO_memcmp(hmac1, hmac2, HMAC_SIZE) != 0) {
        fprintf(stderr, "HMAC mismatch!\n");
        return 1;
    }

    printf("SUCCESS: HMAC values match!\n");

    OPENSSL_cleanse(hmac1, sizeof(hmac1));
    OPENSSL_cleanse(hmac2, sizeof(hmac2));

    return 0;
}
