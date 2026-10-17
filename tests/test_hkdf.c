#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

int main(void) {
    unsigned char shared_secret[32] = {0};
    unsigned char salt[32] = {0};

    unsigned char key1[SESSION_KEY_SIZE];
    unsigned char key2[SESSION_KEY_SIZE];

    
    for (int i = 0; i < 32; i++) {
        shared_secret[i] = (unsigned char)(i + 1);
        salt[i] = (unsigned char)(i + 50);
    }

    if (!derive_session_key(shared_secret, sizeof(shared_secret),
                            salt, sizeof(salt), key1) ||
        !derive_session_key(shared_secret, sizeof(shared_secret),
                            salt, sizeof(salt), key2)) {
        fprintf(stderr, "HKDF failed!\n");
        return 1;
    }

    if (CRYPTO_memcmp(key1, key2, SESSION_KEY_SIZE) == 0) {
        printf("SUCCESS: Session keys match!\n");
    } else {
        printf("ERROR: Session keys do not match!\n");
        return 1;
    }

    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));

    return 0;
}
