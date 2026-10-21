
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"
#include "tunnel_handshake.h"
#include "tunnel_keys.h"
#define KEY_SIZE 32
#define PORT 6000

static int send_all(int fd, const unsigned char *data, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }

    return 1;
}

static int recv_all(int fd, unsigned char *data, size_t len) {
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(fd, data + received, len - received, 0);
        if (n <= 0) return 0;
        received += (size_t)n;
    }

    return 1;
}

int tunnel_handshake_client(TunnelSession *session) {
    int sock = -1;
    int success = 0;
    if (!session) return 0;
    memset(session, 0, sizeof(*session));

    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY *device1_key = NULL;
    EVP_PKEY *peer_key = NULL;

    unsigned char public_key[KEY_SIZE] = {0};
    unsigned char peer_public_key[KEY_SIZE] = {0};
    unsigned char shared_secret[KEY_SIZE] = {0};
    unsigned char salt[32] = {0};
    unsigned char session_key[SESSION_KEY_SIZE] = {0};
unsigned char forward_key[TUNNEL_KEY_SIZE] = {0};
unsigned char reverse_key[TUNNEL_KEY_SIZE] = {0};
    unsigned char confirmation_key[CONFIRM_KEY_SIZE] = {0};
    unsigned char psk[PSK_SIZE] = {0};

    unsigned char transcript[96] = {0};
    unsigned char auth_data[sizeof(transcript) + 20] = {0};
    unsigned char auth_hmac[HMAC_SIZE] = {0};
    unsigned char received_auth_hmac[HMAC_SIZE] = {0};
    unsigned char confirmation_hmac[HMAC_SIZE] = {0};
    unsigned char received_confirmation[HMAC_SIZE] = {0};

    size_t public_len = sizeof(public_key);
    size_t secret_len = sizeof(shared_secret);

    const unsigned char device2_auth_label[] = "Device2 PSK auth";
    const unsigned char device1_auth_label[] = "Device1 PSK auth";
    const unsigned char device2_confirm_label[] = "Device2 confirmation";
    const unsigned char device1_confirm_label[] = "Device1 confirmation";

    struct sockaddr_in address = {0};

    if (!load_psk("secrets/device_psk.hex", psk)) {
        fprintf(stderr, "Device1: Failed to load PSK!\n");
        goto cleanup;
    }

    key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (!key_ctx ||
        EVP_PKEY_keygen_init(key_ctx) <= 0 ||
        EVP_PKEY_keygen(key_ctx, &device1_key) <= 0 ||
        EVP_PKEY_get_raw_public_key(device1_key, public_key, &public_len) <= 0 ||
        public_len != KEY_SIZE) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        goto cleanup;
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = inet_addr("10.0.2.2");

    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connect");
        goto cleanup;
    }

    printf("Device1: Connected to Device2!\n");

    if (!send_all(sock, public_key, KEY_SIZE) ||
        !recv_all(sock, peer_public_key, KEY_SIZE)) {
        fprintf(stderr, "Device1: Public key exchange failed!\n");
        goto cleanup;
    }

    printf("Device1: Public keys exchanged!\n");

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, peer_public_key, KEY_SIZE
    );

    derive_ctx = EVP_PKEY_CTX_new(device1_key, NULL);

    if (!peer_key || !derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0 ||
        secret_len != KEY_SIZE) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("Device1: Shared secret derived!\n");

    if (!recv_all(sock, salt, sizeof(salt))) {
        fprintf(stderr, "Device1: Salt receive failed!\n");
        goto cleanup;
    }

    memcpy(transcript, public_key, KEY_SIZE);
    memcpy(transcript + KEY_SIZE, peer_public_key, KEY_SIZE);
    memcpy(transcript + KEY_SIZE * 2, salt, sizeof(salt));

    memcpy(auth_data, transcript, sizeof(transcript));
    memcpy(
        auth_data + sizeof(transcript),
        device2_auth_label,
        sizeof(device2_auth_label) - 1
    );

    if (!compute_hmac(
            psk, sizeof(psk),
            auth_data,
            sizeof(transcript) + sizeof(device2_auth_label) - 1,
            auth_hmac) ||
        !recv_all(sock, received_auth_hmac, HMAC_SIZE) ||
        CRYPTO_memcmp(auth_hmac, received_auth_hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "Device1: Device2 PSK authentication failed!\n");
        goto cleanup;
    }

    printf("SUCCESS: Device2 PSK authentication verified!\n");

    memcpy(
        auth_data + sizeof(transcript),
        device1_auth_label,
        sizeof(device1_auth_label) - 1
    );

    if (!compute_hmac(
            psk, sizeof(psk),
            auth_data,
            sizeof(transcript) + sizeof(device1_auth_label) - 1,
            auth_hmac) ||
        !send_all(sock, auth_hmac, HMAC_SIZE)) {
        fprintf(stderr, "Device1: PSK authentication send failed!\n");
        goto cleanup;
    }

    if (!derive_session_key(
            shared_secret, secret_len,
            salt, sizeof(salt),
            session_key) ||
        !derive_confirmation_key(
            shared_secret, secret_len,
            salt, sizeof(salt),
            confirmation_key)) {
        fprintf(stderr, "Device1: HKDF failed!\n");
        goto cleanup;
    }

    memcpy(
        auth_data + sizeof(transcript),
        device2_confirm_label,
        sizeof(device2_confirm_label) - 1
    );

    if (!compute_hmac(
            confirmation_key, sizeof(confirmation_key),
            auth_data,
            sizeof(transcript) + sizeof(device2_confirm_label) - 1,
            confirmation_hmac) ||
        !recv_all(sock, received_confirmation, HMAC_SIZE) ||
        CRYPTO_memcmp(
            confirmation_hmac, received_confirmation, HMAC_SIZE
        ) != 0) {
        fprintf(stderr, "Device1: Device2 key confirmation failed!\n");
        goto cleanup;
    }

    printf("SUCCESS: Device2 key confirmation verified!\n");

    memcpy(
        auth_data + sizeof(transcript),
        device1_confirm_label,
        sizeof(device1_confirm_label) - 1
    );

    if (!compute_hmac(
            confirmation_key, sizeof(confirmation_key),
            auth_data,
            sizeof(transcript) + sizeof(device1_confirm_label) - 1,
            confirmation_hmac) ||
        !send_all(sock, confirmation_hmac, HMAC_SIZE)) {
        fprintf(stderr, "Device1: Confirmation send failed!\n");
        goto cleanup;
    }
if (!derive_tunnel_keys(session_key, forward_key, reverse_key)) {
    fprintf(stderr, "Device1: Tunnel key derivation failed!\n");
    goto cleanup;
}

printf("Device1: Directional tunnel keys derived!\n");
    if (!tunnel_session_init(session, session_key, 1)) goto cleanup;

    unsigned char final_ack[HMAC_SIZE] = {0};
    const unsigned char final_label[] = "Device2 final acknowledgment";

    if (!compute_hmac(
            confirmation_key, sizeof(confirmation_key),
            final_label, sizeof(final_label) - 1,
            confirmation_hmac) ||
        !recv_all(sock, final_ack, HMAC_SIZE) ||
        CRYPTO_memcmp(final_ack, confirmation_hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "Device1: Final acknowledgment failed!\n");
        goto cleanup;
    }

    printf("Device1: Authenticated handshake completed!\n");

    success = 1;

cleanup:
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    OPENSSL_cleanse(confirmation_key, sizeof(confirmation_key));
    OPENSSL_cleanse(psk, sizeof(psk));
    OPENSSL_cleanse(auth_hmac, sizeof(auth_hmac));
    OPENSSL_cleanse(received_auth_hmac, sizeof(received_auth_hmac));
    OPENSSL_cleanse(confirmation_hmac, sizeof(confirmation_hmac));
    OPENSSL_cleanse(received_confirmation, sizeof(received_confirmation));

OPENSSL_cleanse(forward_key, sizeof(forward_key));
OPENSSL_cleanse(reverse_key, sizeof(reverse_key));
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(device1_key);
    EVP_PKEY_free(peer_key);

    if (sock >= 0) close(sock);

    if (!success) tunnel_session_cleanup(session);
    return success;
}
