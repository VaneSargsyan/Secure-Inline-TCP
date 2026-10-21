
#ifndef TUNNEL_HANDSHAKE_H
#define TUNNEL_HANDSHAKE_H

#include "tunnel_session.h"

int tunnel_handshake_client(TunnelSession *session);

int tunnel_handshake_server(TunnelSession *session);

#endif
