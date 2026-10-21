
#ifndef TUNNEL_SESSION_H
#define TUNNEL_SESSION_H

#include "tunnel_keys.h"
#include "nonce_manager.h"
#include "replay_protection.h"

typedef struct {
    unsigned char send_key[TUNNEL_KEY_SIZE];
    unsigned char receive_key[TUNNEL_KEY_SIZE];
    NonceManager send_nonce;
    ReplayWindow receive_window;
    int initialized;
} TunnelSession;

int tunnel_session_init(
    TunnelSession *session,
    const unsigned char session_key[SESSION_KEY_SIZE],
    int device_id
);

void tunnel_session_cleanup(TunnelSession *session);

#endif
