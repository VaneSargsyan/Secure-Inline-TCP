#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

uint16_t ipv4_checksum(const void *data, size_t length);

uint16_t tcp_checksum(
    const uint8_t *packet,
    size_t packet_length
);

#endif
