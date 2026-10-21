
#include "payload_crypto.h"
#include "replay_protection.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define UDP_PORT 9001
#define BUFFER_SIZE 2048

static int load_key(unsigned char key[AES_KEY_SIZE]) {
    FILE *file = fopen("secrets/tunnel.key", "rb");

    if (file == NULL) {
        perror("fopen");
        return 0;
    }

    size_t count = fread(key, 1, AES_KEY_SIZE, file);
    int extra = fgetc(file);
    int error = ferror(file);

    fclose(file);

    return count == AES_KEY_SIZE && extra == EOF && !error;
}

static uint64_t read_sequence(const unsigned char *nonce) {
    uint64_t sequence = 0;

    for (int i = 4; i < GCM_NONCE_SIZE; i++) {
        sequence = (sequence << 8) | nonce[i];
    }

    return sequence;
}

static int receive_messages(const unsigned char key[AES_KEY_SIZE]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(UDP_PORT);

    if (inet_pton(AF_INET, "10.0.2.2", &address.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }

    ReplayWindow window = {0};
    unsigned char session_prefix[4] = {0};
    int session_initialized = 0;

    printf("Device2 waiting for encrypted UDP messages...\n");
    fflush(stdout);

    while (1) {
        unsigned char encrypted[BUFFER_SIZE];
        unsigned char decrypted[BUFFER_SIZE];

        ssize_t received = recvfrom(
            fd, encrypted, sizeof(encrypted), 0, NULL, NULL
        );

        if (received < 0) {
            perror("recvfrom");
            close(fd);
            return 1;
        }

        if ((size_t)received < PAYLOAD_OVERHEAD) {
            printf("Invalid packet rejected\n");
            continue;
        }

        size_t decrypted_len = 0;

        if (decrypt_payload(
            key,
            encrypted,
            (size_t)received,
            decrypted,
            sizeof(decrypted) - 1,
            &decrypted_len
        ) != 1) {
            printf("Authentication failed\n");
            continue;
        }

        if (!session_initialized) {
            memcpy(session_prefix, encrypted, 4);
            session_initialized = 1;
        }

        if (memcmp(session_prefix, encrypted, 4) != 0) {
            printf("Unknown session rejected\n");
            continue;
        }

        uint64_t sequence = read_sequence(encrypted);

        if (!replay_accept(&window, sequence)) {
            printf("Replay detected: sequence=%llu\n",
                   (unsigned long long)sequence);
            continue;
        }

        decrypted[decrypted_len] = '\0';

        printf("Accepted sequence=%llu: %s\n",
               (unsigned long long)sequence, decrypted);
        fflush(stdout);
    }
}

static int send_messages(const unsigned char key[AES_KEY_SIZE]) {
    const unsigned char message[] = "Hello securely from Device1";

    unsigned char prefix[4];

    if (RAND_bytes(prefix, sizeof(prefix)) != 1) {
        fprintf(stderr, "Random prefix generation failed\n");
        return 1;
    }

    NonceManager manager = {0};

    if (nonce_manager_init(&manager, prefix) != 1) {
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in destination = {0};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(UDP_PORT);

    if (inet_pton(AF_INET, "10.0.2.2", &destination.sin_addr) != 1) {
        close(fd);
        return 1;
    }

    for (int i = 0; i < 3; i++) {
        unsigned char encrypted[BUFFER_SIZE];
        size_t encrypted_len = 0;

        if (encrypt_payload(
            key,
            &manager,
            message,
            sizeof(message) - 1,
            encrypted,
            sizeof(encrypted),
            &encrypted_len
        ) != 1) {
            close(fd);
            return 1;
        }

        int copies = i == 0 ? 2 : 1;

        for (int j = 0; j < copies; j++) {
            ssize_t sent = sendto(
                fd,
                encrypted,
                encrypted_len,
                0,
                (struct sockaddr *)&destination,
                sizeof(destination)
            );

            if (sent != (ssize_t)encrypted_len) {
                perror("sendto");
                close(fd);
                return 1;
            }
        }

        printf("Sent sequence=%d, copies=%d\n", i, copies);
    }

    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s send|receive\n", argv[0]);
        return 1;
    }

    unsigned char key[AES_KEY_SIZE];

    if (!load_key(key)) {
        fprintf(stderr, "Unable to load tunnel key\n");
        return 1;
    }

    if (strcmp(argv[1], "receive") == 0) {
        return receive_messages(key);
    }

    if (strcmp(argv[1], "send") == 0) {
        return send_messages(key);
    }

    fprintf(stderr, "Invalid mode\n");
    return 1;
}
