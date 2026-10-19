
#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const unsigned char *ip_header;
    size_t ip_header_len;

    const unsigned char *tcp_header;
    size_t tcp_header_len;

    const unsigned char *payload;
    size_t payload_len;

    uint32_t source_ip;
    uint32_t destination_ip;

    uint16_t source_port;
    uint16_t destination_port;
} ParsedPacket;

int parse_tcp_packet(
    const unsigned char *packet,
    size_t packet_len,
    ParsedPacket *result
);

#endif
