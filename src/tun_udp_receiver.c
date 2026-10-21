#include "tun_device.h"
#include "payload_crypto.h"
#include "replay_protection.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 9002
#define BUFFER_SIZE 65535

static uint64_t get_sequence(const unsigned char *nonce) {
    uint64_t sequence = 0;

    for (int i = 4; i < GCM_NONCE_SIZE; i++) {
        sequence = (sequence << 8) | nonce[i];
    }

    return sequence;
}

int main(void) {
    unsigned char key[AES_KEY_SIZE];

    FILE *file = fopen("secrets/tunnel.key", "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }

    if (fread(key, 1, sizeof(key), file) != sizeof(key)) {
        fclose(file);
        fprintf(stderr, "Invalid key\n");
        return 1;
    }
    fclose(file);
int tun = tun_open("tun-d2");

if (tun < 0) {
    perror("tun_open");
    return 1;
}
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "10.0.2.2", &address.sin_addr) != 1) {
        close(sock);
        return 1;
    }

    if (bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    ReplayWindow window = {0};
    unsigned char session_prefix[4] = {0};
    int session_initialized = 0;

    unsigned char encrypted[BUFFER_SIZE + PAYLOAD_OVERHEAD];
    unsigned char packet[BUFFER_SIZE];

    printf("Device2 waiting for encrypted IP packets...\n");
    fflush(stdout);

    while (1) {
        ssize_t received = recvfrom(
            sock, encrypted, sizeof(encrypted), 0, NULL, NULL
        );

        if (received < (ssize_t)PAYLOAD_OVERHEAD) {
            continue;
        }

        size_t packet_length = 0;

        if (!decrypt_payload(
                key,
                encrypted,
                (size_t)received,
                packet,
                sizeof(packet),
                &packet_length)) {
            printf("Authentication failed\n");
            fflush(stdout);
            continue;
        }

        if (!session_initialized) {
            memcpy(session_prefix, encrypted, sizeof(session_prefix));
            session_initialized = 1;
        }

        if (memcmp(session_prefix, encrypted, sizeof(session_prefix)) != 0) {
            printf("Different session rejected\n");
            fflush(stdout);
            continue;
        }

        uint64_t sequence = get_sequence(encrypted);

        if (!replay_accept(&window, sequence)) {
            printf("Replay rejected: %llu\n",
                   (unsigned long long)sequence);
            fflush(stdout);
            continue;
        }

        if (packet_length < 20 || (packet[0] >> 4) != 4) {
            printf("Invalid IPv4 packet\n");
            fflush(stdout);
            continue;
        }
ssize_t written = tun_write_packet(tun, packet, packet_length);

if (written != (ssize_t)packet_length) {
    perror("tun_write_packet");
    break;
}

printf("Packet written to tun-d2: %zd bytes\n", written);
fflush(stdout);
        printf("Decrypted IPv4 packet: %zu bytes, sequence=%llu\n",
               packet_length, (unsigned long long)sequence);
        fflush(stdout);
    }
close(tun);	
    close(sock);
    return 0;
}
