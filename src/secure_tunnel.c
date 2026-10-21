
#include "tunnel_handshake.h"
#include "tun_device.h"
#include "payload_crypto.h"
#include "replay_protection.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define UDP_PORT 9003
#define MAX_PACKET 65507
#define MAX_IP_PACKET (MAX_PACKET - PAYLOAD_OVERHEAD)

static uint64_t packet_sequence(const unsigned char *packet) {
    uint64_t sequence = 0;

    for (int i = 4; i < GCM_NONCE_SIZE; i++) {
        sequence = (sequence << 8) | packet[i];
    }

    return sequence;
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "1") != 0 &&
                      strcmp(argv[1], "2") != 0)) {
        fprintf(stderr, "Usage: %s 1|2\n", argv[0]);
        return 1;
    }

    int device_id = atoi(argv[1]);
    TunnelSession session = {0};

    int authenticated = device_id == 1
        ? tunnel_handshake_client(&session)
        : tunnel_handshake_server(&session);

    if (!authenticated || !session.initialized) {
        fprintf(stderr, "Authenticated handshake failed\n");
        tunnel_session_cleanup(&session);
        return 1;
    }

    const char *tun_name = device_id == 1 ? "tun-d1" : "tun-d2";
    const char *local_ip = device_id == 1 ? "10.0.2.1" : "10.0.2.2";
    const char *peer_ip = device_id == 1 ? "10.0.2.2" : "10.0.2.1";

    int tun = tun_open(tun_name);

    if (tun < 0) {
        perror("tun_open");
        tunnel_session_cleanup(&session);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("socket");
        close(tun);
        tunnel_session_cleanup(&session);
        return 1;
    }

    struct sockaddr_in local = {0};
    struct sockaddr_in peer = {0};

    local.sin_family = AF_INET;
    local.sin_port = htons(UDP_PORT);

    peer.sin_family = AF_INET;
    peer.sin_port = htons(UDP_PORT);

    if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1 ||
        inet_pton(AF_INET, peer_ip, &peer.sin_addr) != 1 ||
        bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0 ||
        connect(sock, (struct sockaddr *)&peer, sizeof(peer)) < 0) {
        perror("UDP setup");
        close(sock);
        close(tun);
        tunnel_session_cleanup(&session);
        return 1;
    }

    struct pollfd descriptors[2] = {
        {.fd = tun, .events = POLLIN},
        {.fd = sock, .events = POLLIN}
    };

    unsigned char packet[MAX_IP_PACKET];
    unsigned char encrypted[MAX_PACKET];

    printf("Device%d: Encrypted tunnel ready\n", device_id);
    fflush(stdout);

    int status = 0;

    while (1) {
        int ready = poll(descriptors, 2, -1);

        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            status = 1;
            break;
        }

        if (descriptors[0].revents & POLLIN) {
            ssize_t length = tun_read_packet(tun, packet, sizeof(packet));

            if (length < 0) {
                perror("tun_read_packet");
                status = 1;
                break;
            }

            if (length > 0 && (packet[0] >> 4) == 4) {
                size_t encrypted_length = 0;

                if (!encrypt_payload(
                        session.send_key,
                        &session.send_nonce,
                        packet,
                        (size_t)length,
                        encrypted,
                        sizeof(encrypted),
                        &encrypted_length)) {
                    fprintf(stderr, "Encryption failed\n");
                    status = 1;
                    break;
                }

                if (send(sock, encrypted, encrypted_length, 0) !=
                    (ssize_t)encrypted_length) {
                    perror("send");
                    status = 1;
                    break;
                }

                printf("Device%d TX: %zd bytes\n", device_id, length);
                fflush(stdout);
            }
        }

        if (descriptors[1].revents & POLLIN) {
            ssize_t length = recv(sock, encrypted, sizeof(encrypted), 0);

            if (length < (ssize_t)PAYLOAD_OVERHEAD) {
                continue;
            }

            size_t decrypted_length = 0;

            if (!decrypt_payload(
                    session.receive_key,
                    encrypted,
                    (size_t)length,
                    packet,
                    sizeof(packet),
                    &decrypted_length)) {
                fprintf(stderr, "Authentication failed\n");
                continue;
            }

            uint64_t sequence = packet_sequence(encrypted);

            if (!replay_accept(&session.receive_window, sequence)) {
                fprintf(stderr, "Replay rejected\n");
                continue;
            }

            if (decrypted_length < 20 ||
                (packet[0] >> 4) != 4 ||
                ((size_t)(packet[0] & 15) * 4) > decrypted_length) {
                fprintf(stderr, "Invalid IPv4 packet\n");
                continue;
            }

            if (tun_write_packet(tun, packet, decrypted_length) !=
                (ssize_t)decrypted_length) {
                perror("tun_write_packet");
                status = 1;
                break;
            }

            printf("Device%d RX: %zu bytes\n",
                   device_id, decrypted_length);
            fflush(stdout);
        }

        if ((descriptors[0].revents | descriptors[1].revents) &
            (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "Tunnel descriptor error\n");
            status = 1;
            break;
        }
    }

    close(sock);
    close(tun);
    tunnel_session_cleanup(&session);
    return status;
}
