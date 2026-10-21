
#include "tunnel_keys.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char session_key[SESSION_KEY_SIZE];
    unsigned char second_session_key[SESSION_KEY_SIZE];

    for (size_t i = 0; i < SESSION_KEY_SIZE; i++) {
        session_key[i] = (unsigned char)i;
        second_session_key[i] = (unsigned char)(i + 1);
    }

    unsigned char forward[TUNNEL_KEY_SIZE];
    unsigned char reverse[TUNNEL_KEY_SIZE];
    unsigned char forward_again[TUNNEL_KEY_SIZE];
    unsigned char reverse_again[TUNNEL_KEY_SIZE];
    unsigned char other_forward[TUNNEL_KEY_SIZE];
    unsigned char other_reverse[TUNNEL_KEY_SIZE];

    assert(derive_tunnel_keys(session_key, forward, reverse) == 1);

    assert(memcmp(forward, reverse, TUNNEL_KEY_SIZE) != 0);

    assert(derive_tunnel_keys(
        session_key, forward_again, reverse_again
    ) == 1);

    assert(memcmp(forward, forward_again, TUNNEL_KEY_SIZE) == 0);
    assert(memcmp(reverse, reverse_again, TUNNEL_KEY_SIZE) == 0);

    assert(derive_tunnel_keys(
        second_session_key, other_forward, other_reverse
    ) == 1);

    assert(memcmp(forward, other_forward, TUNNEL_KEY_SIZE) != 0);
    assert(memcmp(reverse, other_reverse, TUNNEL_KEY_SIZE) != 0);

    printf("Directional tunnel key tests passed\n");

    return 0;
}
