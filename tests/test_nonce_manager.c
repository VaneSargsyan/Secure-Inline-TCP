
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "nonce_manager.h"

int main(void) {
    NonceManager manager;
    unsigned char prefix[4] = {0x12, 0x34, 0x56, 0x78};
    unsigned char nonce1[GCM_NONCE_SIZE];
    unsigned char nonce2[GCM_NONCE_SIZE];

    if (!nonce_manager_init(&manager, prefix)) {
        return 1;
    }

    if (!nonce_manager_next(&manager, nonce1) ||
        !nonce_manager_next(&manager, nonce2)) {
        return 1;
    }

    if (memcmp(nonce1, nonce2, GCM_NONCE_SIZE) == 0) {
        fprintf(stderr, "ERROR: Duplicate nonce!\n");
        return 1;
    }

    printf("SUCCESS: Consecutive nonces are unique!\n");

    manager.counter = UINT64_MAX;

    if (!nonce_manager_next(&manager, nonce1)) {
        return 1;
    }

    if (nonce_manager_next(&manager, nonce2)) {
        fprintf(stderr, "ERROR: Counter overflow accepted!\n");
        return 1;
    }

    printf("SUCCESS: Counter exhaustion handled!\n");

    return 0;
}
