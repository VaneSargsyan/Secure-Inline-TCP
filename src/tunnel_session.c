
#include "tunnel_session.h"

#include <openssl/crypto.h>
#include <string.h>

int tunnel_session_init(
    TunnelSession *session,
    const unsigned char session_key[SESSION_KEY_SIZE],
    int device_id
) {
    if (!session || !session_key ||
        (device_id != 1 && device_id != 2)) {
        return 0;
    }

    memset(session, 0, sizeof(*session));

    unsigned char forward[TUNNEL_KEY_SIZE] = {0};
    unsigned char reverse[TUNNEL_KEY_SIZE] = {0};

    int success = derive_tunnel_keys(
        session_key, forward, reverse
    );

    if (!success) {
        goto cleanup;
    }

    if (device_id == 1) {
        memcpy(session->send_key, forward, TUNNEL_KEY_SIZE);
        memcpy(session->receive_key, reverse, TUNNEL_KEY_SIZE);
    } else {
        memcpy(session->send_key, reverse, TUNNEL_KEY_SIZE);
        memcpy(session->receive_key, forward, TUNNEL_KEY_SIZE);
    }

    unsigned char prefix[4] = {0};

    if (!nonce_manager_init(&session->send_nonce, prefix)) {
        success = 0;
        goto cleanup;
    }

    session->initialized = 1;

cleanup:
    OPENSSL_cleanse(forward, sizeof(forward));
    OPENSSL_cleanse(reverse, sizeof(reverse));

    if (!success) {
        tunnel_session_cleanup(session);
    }

    return success;
}

void tunnel_session_cleanup(TunnelSession *session) {
    if (session) {
        OPENSSL_cleanse(session, sizeof(*session));
    }
}
