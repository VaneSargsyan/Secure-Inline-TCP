
#include "tun_device.h"
#include "payload_crypto.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_PACKET_SIZE 65535

int main(void) {
    unsigned char key[AES_KEY_SIZE] = {0};
    unsigned char prefix[4] = {1, 2, 3, 4};

    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = (unsigned char)(i + 1);
    }

    NonceManager manager = {0};

    if (nonce_manager_init(&manager, prefix) != 1) {
        fprintf(stderr, "Nonce initialization failed\n");
        return 1;
    }

    int fd = tun_open("tun-test");

    if (fd < 0) {
        perror("tun_open");
        return 1;
    }

    unsigned char packet[MAX_PACKET_SIZE];
    unsigned char encrypted[MAX_PACKET_SIZE + PAYLOAD_OVERHEAD];
    unsigned char decrypted[MAX_PACKET_SIZE];

    printf("Waiting for IPv4 packet...\n");
    fflush(stdout);

    ssize_t packet_len;

    do {
        packet_len = tun_read_packet(fd, packet, sizeof(packet));

        if (packet_len <= 0) {
            perror("tun_read_packet");
            close(fd);
            return 1;
        }
    } while ((packet[0] >> 4) != 4);

    printf("Received IPv4 packet: %zd bytes\n", packet_len);

    size_t encrypted_len = 0;

    if (encrypt_payload(
        key,
        &manager,
        packet,
        (size_t)packet_len,
        encrypted,
        sizeof(encrypted),
        &encrypted_len
    ) != 1) {
        fprintf(stderr, "Encryption failed\n");
        close(fd);
        return 1;
    }

    printf("Encrypted packet: %zu bytes\n", encrypted_len);

    size_t decrypted_len = 0;

    if (decrypt_payload(
        key,
        encrypted,
        encrypted_len,
        decrypted,
        sizeof(decrypted),
        &decrypted_len
    ) != 1) {
        fprintf(stderr, "Decryption failed\n");
        close(fd);
        return 1;
    }

    if (decrypted_len != (size_t)packet_len ||
        memcmp(packet, decrypted, decrypted_len) != 0) {
        fprintf(stderr, "Packet integrity check failed\n");
        close(fd);
        return 1;
    }

    printf("Decrypted packet: %zu bytes\n", decrypted_len);
    printf("Original packet restored successfully\n");

    encrypted[GCM_NONCE_SIZE] ^= 0x01;

    size_t rejected_len = 0;

    if (decrypt_payload(
        key,
        encrypted,
        encrypted_len,
        decrypted,
        sizeof(decrypted),
        &rejected_len
    ) == 1) {
        fprintf(stderr, "Tampered packet was accepted\n");
        close(fd);
        return 1;
    }

    printf("Tampered packet rejected successfully\n");
    printf("TUN + AES-GCM integration test passed\n");

    close(fd);
    return 0;
}
