
#include "tun_device.h"
#include "payload_crypto.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 9002
#define BUFFER_SIZE 65535

int main(void) {
    unsigned char key[AES_KEY_SIZE];

    FILE *file = fopen("secrets/tunnel.key", "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }

    if (fread(key, 1, sizeof(key), file) != sizeof(key)) {
        fclose(file);
        return 1;
    }
    fclose(file);

    int tun = tun_open("tun-d1");
    if (tun < 0) {
        perror("tun_open");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        close(tun);
        return 1;
    }

    struct sockaddr_in destination = {0};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(PORT);
    inet_pton(AF_INET, "10.0.2.2", &destination.sin_addr);

    unsigned char prefix[4];
    if (RAND_bytes(prefix, sizeof(prefix)) != 1) {
        close(sock);
        close(tun);
        return 1;
    }

    NonceManager manager;
    nonce_manager_init(&manager, prefix);

    unsigned char packet[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + PAYLOAD_OVERHEAD];

    printf("Waiting for IPv4 packets on tun-d1...\n");
    fflush(stdout);

    while (1) {
        ssize_t length = tun_read_packet(tun, packet, sizeof(packet));

        if (length <= 0) {
            continue;
        }

        if ((packet[0] >> 4) != 4) {
            continue;
        }

        size_t encrypted_length = 0;

        if (!encrypt_payload(
                key,
                &manager,
                packet,
                (size_t)length,
                encrypted,
                sizeof(encrypted),
                &encrypted_length)) {
            fprintf(stderr, "Encryption failed\n");
            break;
        }

        ssize_t sent = sendto(
            sock,
            encrypted,
            encrypted_length,
            0,
            (struct sockaddr *)&destination,
            sizeof(destination)
        );

        if (sent != (ssize_t)encrypted_length) {
            perror("sendto");
            break;
        }

        printf("IPv4: %zd bytes -> encrypted UDP: %zu bytes\n",
               length, encrypted_length);
        fflush(stdout);
    }

    close(sock);
    close(tun);
    return 0;
}
