#include "tunnel_handshake.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 1;
    }

    TunnelSession session = {0};
    int success = 0;

    if (argv[1][0] == '1') {
        success = tunnel_handshake_client(&session);
    } else if (argv[1][0] == '2') {
        success = tunnel_handshake_server(&session);
    } else {
        return 1;
    }

    if (!success || !session.initialized) {
        fprintf(stderr, "Handshake integration failed\n");
        tunnel_session_cleanup(&session);
        return 1;
    }

    printf("Handshake + TunnelSession integration passed\n");
    tunnel_session_cleanup(&session);
    return 0;
}
