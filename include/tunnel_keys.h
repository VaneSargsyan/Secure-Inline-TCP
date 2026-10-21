
#ifndef TUNNEL_KEYS_H
#define TUNNEL_KEYS_H

#include "crypto_utils.h"

#define TUNNEL_KEY_SIZE 32

int derive_tunnel_keys(
    const unsigned char session_key[SESSION_KEY_SIZE],
    unsigned char device1_to_device2[TUNNEL_KEY_SIZE],
    unsigned char device2_to_device1[TUNNEL_KEY_SIZE]
);

#endif
