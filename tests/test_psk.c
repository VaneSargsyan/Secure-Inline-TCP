#include <stdio.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

int main(void) {
    unsigned char psk[PSK_SIZE] = {0};

    if (!load_psk("secrets/device_psk.hex", psk)) {
        fprintf(stderr, "ERROR: Failed to load PSK!\n");
        return 1;
    }

    printf("SUCCESS: PSK loaded successfully!\n");

    OPENSSL_cleanse(psk, sizeof(psk));

    return 0;
}
