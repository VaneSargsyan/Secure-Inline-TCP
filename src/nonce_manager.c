
#include "nonce_manager.h"

#include <stdint.h>
#include <string.h>

int nonce_manager_init(
    NonceManager *manager,
    const unsigned char prefix[4]
) {
    if (!manager || !prefix) {
        return 0;
    }

    memcpy(manager->prefix, prefix, 4);
    manager->counter = 0;
    manager->exhausted = 0;

    return 1;
}

int nonce_manager_next(
    NonceManager *manager,
    unsigned char nonce[GCM_NONCE_SIZE]
) {
    if (!manager || !nonce || manager->exhausted) {
        return 0;
    }

    memcpy(nonce, manager->prefix, 4);

    uint64_t value = manager->counter;

    for (int i = 11; i >= 4; i--) {
        nonce[i] = (unsigned char)(value & 0xFF);
        value >>= 8;
    }

    if (manager->counter == UINT64_MAX) {
        manager->exhausted = 1;
    } else {
        manager->counter++;
    }

    return 1;
}
