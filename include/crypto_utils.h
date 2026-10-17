#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>

#define SESSION_KEY_SIZE 32

int derive_session_key(
    const unsigned char *shared_secret,
    size_t secret_len,
    const unsigned char *salt,
    size_t salt_len,
    unsigned char session_key[SESSION_KEY_SIZE]
);

#define HMAC_SIZE 32

int compute_hmac(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *data,
    size_t data_len,
    unsigned char output[HMAC_SIZE]
);

#define CONFIRM_KEY_SIZE 32

int derive_confirmation_key(
    const unsigned char *shared_secret,
    size_t secret_len,
    const unsigned char *salt,
    size_t salt_len,
    unsigned char confirmation_key[CONFIRM_KEY_SIZE]
);


#endif
