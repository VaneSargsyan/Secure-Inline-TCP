
#include "packet_parser.h"
#include "payload_crypto.h"
#include "checksum.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HEADER_SIZE 40
#define MAX_PACKET_SIZE 512

static void write16(unsigned char *p, uint16_t value) {
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static void write32(unsigned char *p, uint32_t value) {
    p[0] = (unsigned char)(value >> 24);
    p[1] = (unsigned char)(value >> 16);
    p[2] = (unsigned char)(value >> 8);
    p[3] = (unsigned char)value;
}

static void update_checksums(unsigned char *packet, size_t len) {
    write16(packet + 10, 0);
    write16(packet + 36, 0);

    write16(packet + 10, ipv4_checksum(packet, 20));
    write16(packet + 36, tcp_checksum(packet, len));
}

static void build_packet(
    unsigned char *packet,
    const unsigned char *payload,
    size_t payload_len
) {
    size_t len = HEADER_SIZE + payload_len;

    memset(packet, 0, len);

    packet[0] = 0x45;
    write16(packet + 2, (uint16_t)len);
    packet[8] = 64;
    packet[9] = 6;

    write32(packet + 12, 0x0A000101);
    write32(packet + 16, 0x0A000302);

    write16(packet + 20, 45000);
    write16(packet + 22, 5000);

    write32(packet + 24, 1000);
    packet[32] = 0x50;
    packet[33] = 0x18;
    write16(packet + 34, 4096);

    memcpy(packet + HEADER_SIZE, payload, payload_len);

    update_checksums(packet, len);
}

int main(void) {
    unsigned char key[AES_KEY_SIZE] = {0};
    unsigned char prefix[4] = {1, 2, 3, 4};

    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = (unsigned char)(i + 1);
    }

    NonceManager manager = {0};
    assert(nonce_manager_init(&manager, prefix) == 1);

    const unsigned char message[] = "Secure TCP packet";
    size_t message_len = sizeof(message) - 1;

    unsigned char original[MAX_PACKET_SIZE] = {0};
    unsigned char encrypted_packet[MAX_PACKET_SIZE] = {0};
    unsigned char restored[MAX_PACKET_SIZE] = {0};

    size_t original_len = HEADER_SIZE + message_len;

    build_packet(original, message, message_len);

    ParsedPacket parsed = {0};

    assert(parse_tcp_packet(
        original, original_len, &parsed
    ) == 1);

    assert(parsed.payload_len == message_len);
    assert(memcmp(parsed.payload, message, message_len) == 0);

    printf("Original packet parsing: PASSED\n");

    memcpy(encrypted_packet, original, HEADER_SIZE);

    size_t encrypted_len = 0;

    assert(encrypt_payload(
        key,
        &manager,
        parsed.payload,
        parsed.payload_len,
        encrypted_packet + HEADER_SIZE,
        MAX_PACKET_SIZE - HEADER_SIZE,
        &encrypted_len
    ) == 1);

    size_t encrypted_packet_len = HEADER_SIZE + encrypted_len;

    assert(encrypted_packet_len <= MAX_PACKET_SIZE);
    assert(encrypted_packet_len <= UINT16_MAX);

    write16(
        encrypted_packet + 2,
        (uint16_t)encrypted_packet_len
    );

    update_checksums(encrypted_packet, encrypted_packet_len);

    ParsedPacket encrypted_parsed = {0};

    assert(parse_tcp_packet(
        encrypted_packet,
        encrypted_packet_len,
        &encrypted_parsed
    ) == 1);

    assert(encrypted_parsed.payload_len ==
           message_len + PAYLOAD_OVERHEAD);

    printf("Encrypted packet construction: PASSED\n");

    memcpy(restored, encrypted_packet, HEADER_SIZE);

    size_t restored_payload_len = 0;

    assert(decrypt_payload(
        key,
        encrypted_parsed.payload,
        encrypted_parsed.payload_len,
        restored + HEADER_SIZE,
        MAX_PACKET_SIZE - HEADER_SIZE,
        &restored_payload_len
    ) == 1);

    assert(restored_payload_len == message_len);

    size_t restored_packet_len =
        HEADER_SIZE + restored_payload_len;

    write16(restored + 2, (uint16_t)restored_packet_len);

    update_checksums(restored, restored_packet_len);

    ParsedPacket restored_parsed = {0};

    assert(parse_tcp_packet(
        restored,
        restored_packet_len,
        &restored_parsed
    ) == 1);

    assert(restored_parsed.payload_len == message_len);

    assert(memcmp(
        restored_parsed.payload,
        message,
        message_len
    ) == 0);

    assert(restored_packet_len == original_len);

    printf("Original payload restoration: PASSED\n");

    encrypted_packet[HEADER_SIZE + GCM_NONCE_SIZE] ^= 0x01;

    size_t rejected_len = 0;

    assert(decrypt_payload(
        key,
        encrypted_packet + HEADER_SIZE,
        encrypted_len,
        restored + HEADER_SIZE,
        MAX_PACKET_SIZE - HEADER_SIZE,
        &rejected_len
    ) != 1);

    printf("Tampered encrypted packet rejection: PASSED\n");
    printf("All encrypted packet integration tests passed\n");

    return 0;
}
