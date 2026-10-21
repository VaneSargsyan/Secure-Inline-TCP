
#include "payload_crypto.h"
#include "tcp_seq.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char key[AES_KEY_SIZE] = {0};
    unsigned char prefix[4] = {1, 2, 3, 4};

    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = (unsigned char)(i + 1);
    }

    NonceManager manager = {0};
    assert(nonce_manager_init(&manager, prefix) == 1);

    const unsigned char message1[] = "Hello from PC1";
    const unsigned char message2[] = "Second TCP segment";

    const unsigned char *messages[] = {
        message1,
        message2
    };

    size_t lengths[] = {
        sizeof(message1) - 1,
        sizeof(message2) - 1
    };

    static TcpSegmentTable segments = {0};

    uint32_t original_seq = 1000;

    for (size_t i = 0; i < 2; i++) {
        unsigned char encrypted[256] = {0};
        unsigned char decrypted[256] = {0};

        size_t encrypted_len = 0;
        size_t decrypted_len = 0;

        assert(encrypt_payload(
            key,
            &manager,
            messages[i],
            lengths[i],
            encrypted,
            sizeof(encrypted),
            &encrypted_len
        ) == 1);

        assert(encrypted_len == lengths[i] + PAYLOAD_OVERHEAD);

        TcpSegmentMapping mapping = {0};

        assert(tcp_segment_table_add(
            &segments,
            original_seq,
            (uint32_t)lengths[i],
            (uint32_t)encrypted_len,
            &mapping
        ) == TCP_SEGMENT_NEW);

        printf(
            "Segment %zu: original SEQ=%u, encrypted SEQ=%u\n",
            i + 1,
            mapping.original_seq,
            mapping.translated_seq
        );

        assert(decrypt_payload(
            key,
            encrypted,
            encrypted_len,
            decrypted,
            sizeof(decrypted),
            &decrypted_len
        ) == 1);

        assert(decrypted_len == lengths[i]);
        assert(memcmp(
            decrypted,
            messages[i],
            lengths[i]
        ) == 0);

        uint32_t translated_ack =
            tcp_segment_translated_end(&mapping);

        uint32_t restored_ack = 0;

        assert(tcp_translate_ack(
            &segments,
            translated_ack,
            &restored_ack
        ) == TCP_ACK_MAPPED);

        assert(restored_ack ==
               original_seq + (uint32_t)lengths[i]);

        original_seq += (uint32_t)lengths[i];
    }

    assert(segments.count == 2);

    printf("Device1 encryption: PASSED\n");
    printf("Device2 decryption: PASSED\n");
    printf("TCP SEQ mapping: PASSED\n");
    printf("TCP ACK mapping: PASSED\n");
    printf("Offline device pipeline tests passed\n");

    return 0;
}
