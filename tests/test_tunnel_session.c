
#include "tunnel_session.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char session_key[SESSION_KEY_SIZE];

    for (size_t i = 0; i < SESSION_KEY_SIZE; i++) {
        session_key[i] = (unsigned char)i;
    }

    TunnelSession device1 = {0};
    TunnelSession device2 = {0};

    assert(tunnel_session_init(&device1, session_key, 1) == 1);
    assert(tunnel_session_init(&device2, session_key, 2) == 1);

    assert(device1.initialized == 1);
    assert(device2.initialized == 1);

    assert(memcmp(
        device1.send_key,
        device2.receive_key,
        TUNNEL_KEY_SIZE
    ) == 0);

    assert(memcmp(
        device2.send_key,
        device1.receive_key,
        TUNNEL_KEY_SIZE
    ) == 0);

    assert(memcmp(
        device1.send_key,
        device1.receive_key,
        TUNNEL_KEY_SIZE
    ) != 0);

    unsigned char nonce1[GCM_NONCE_SIZE];
    unsigned char nonce2[GCM_NONCE_SIZE];

    assert(nonce_manager_next(&device1.send_nonce, nonce1) == 1);
    assert(nonce_manager_next(&device1.send_nonce, nonce2) == 1);
    assert(memcmp(nonce1, nonce2, GCM_NONCE_SIZE) != 0);

    assert(replay_accept(&device2.receive_window, 0) == 1);
    assert(replay_accept(&device2.receive_window, 0) == 0);
    assert(replay_accept(&device2.receive_window, 1) == 1);

    tunnel_session_cleanup(&device1);
    tunnel_session_cleanup(&device2);

    assert(device1.initialized == 0);
    assert(device2.initialized == 0);

    printf("Tunnel session tests passed\n");

    return 0;
}
