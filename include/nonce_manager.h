
#ifndef NONCE_MANAGER_H
#define NONCE_MANAGER_H

#include <stdint.h>
#include "aes_gcm.h"

typedef struct {
    unsigned char prefix[4];
    uint64_t counter;
    int exhausted;
} NonceManager;

int nonce_manager_init(
    NonceManager *manager,
    const unsigned char prefix[4]
);

int nonce_manager_next(
    NonceManager *manager,
    unsigned char nonce[GCM_NONCE_SIZE]
);

#endif
