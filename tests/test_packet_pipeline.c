
#include "packet_parser.h"
#include "checksum.h"
#include "tcp_connection.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void write16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void create_packet(
    uint8_t *packet,
    uint32_t source_ip,
    uint32_t destination_ip,
    uint16_t source_port,
    uint16_t destination_port
) {
    memset(packet, 0, 40);

    packet[0] = 0x45;
    write16(packet + 2, 40);
    packet[8] = 64;
    packet[9] = 6;

    write32(packet + 12, source_ip);
    write32(packet + 16, destination_ip);

    write16(packet + 20, source_port);
    write16(packet + 22, destination_port);

    write32(packet + 24, 1000);
    packet[32] = 0x50;
    packet[33] = 0x02;
    write16(packet + 34, 4096);

    write16(packet + 10, ipv4_checksum(packet, 20));
    write16(packet + 36, tcp_checksum(packet, 40));
}

int main(void) {
    uint8_t packet[40];

    create_packet(
        packet,
        0x0A000101,
        0x0A000302,
        45000,
        5000
    );

    ParsedPacket parsed = {0};

    assert(parse_tcp_packet(
        packet, sizeof(packet), &parsed
    ) == 1);

    assert(parsed.ip_header_len == 20);
    assert(parsed.tcp_header_len == 20);
    assert(parsed.payload_len == 0);

    assert(parsed.source_port == 45000);
    assert(parsed.destination_port == 5000);

    assert(read16(packet + 10) != 0);
    assert(read16(packet + 36) != 0);

    static TcpConnectionTable connections = {0};

    TcpFlowKey forward_key = {
        .src_ip = parsed.source_ip,
        .dst_ip = parsed.destination_ip,
        .src_port = parsed.source_port,
        .dst_port = parsed.destination_port
    };

    TcpConnection *connection =
        tcp_connection_add(&connections, &forward_key);

    assert(connection != NULL);
    assert(connection->status == TCP_CONN_NEW);
    assert(connections.count == 1);

    assert(tcp_connection_direction(
        connection, &forward_key
    ) == TCP_DIRECTION_FORWARD);

    assert(tcp_connection_process_event(
        connection, TCP_EVENT_SYN
    ) == 1);

    assert(connection->status == TCP_CONN_SYN_SENT);

    TcpFlowKey reverse_key = {
        .src_ip = forward_key.dst_ip,
        .dst_ip = forward_key.src_ip,
        .src_port = forward_key.dst_port,
        .dst_port = forward_key.src_port
    };

    assert(tcp_connection_find_bidirectional(
        &connections, &reverse_key
    ) == connection);

    assert(tcp_connection_direction(
        connection, &reverse_key
    ) == TCP_DIRECTION_REVERSE);

    assert(tcp_connection_process_event(
        connection, TCP_EVENT_SYN_ACK
    ) == 1);

    assert(tcp_connection_process_event(
        connection, TCP_EVENT_ACK
    ) == 1);

    assert(connection->status == TCP_CONN_ESTABLISHED);

uint8_t data_packet[45];

memset(data_packet, 0, sizeof(data_packet));

create_packet(
    data_packet,
    0x0A000101,
    0x0A000302,
    45000,
    5000
);

write16(data_packet + 2, sizeof(data_packet));
data_packet[33] = 0x18;

memcpy(data_packet + 40, "HELLO", 5);

write16(data_packet + 10, 0);
write16(data_packet + 36, 0);

write16(data_packet + 10, ipv4_checksum(data_packet, 20));
write16(data_packet + 36, tcp_checksum(data_packet, sizeof(data_packet)));

ParsedPacket data_parsed = {0};

assert(parse_tcp_packet(
    data_packet, sizeof(data_packet), &data_parsed
) == 1);

assert(data_parsed.payload_len == 5);
assert(memcmp(data_parsed.payload, "HELLO", 5) == 0);

uint16_t original_tcp_checksum = read16(data_packet + 36);

memcpy(data_packet + 40, "WORLD", 5);

write16(data_packet + 36, 0);
write16(data_packet + 36, tcp_checksum(data_packet, sizeof(data_packet)));

assert(read16(data_packet + 36) != original_tcp_checksum);

assert(parse_tcp_packet(
    data_packet, sizeof(data_packet), &data_parsed
) == 1);

assert(memcmp(data_parsed.payload, "WORLD", 5) == 0);


uint16_t saved_tcp_checksum = read16(data_packet + 36);

write16(data_packet + 36, 0);

uint16_t calculated_tcp_checksum =
    tcp_checksum(data_packet, sizeof(data_packet));

assert(saved_tcp_checksum == calculated_tcp_checksum);

data_packet[40] ^= 0x01;

uint16_t corrupted_tcp_checksum =
    tcp_checksum(data_packet, sizeof(data_packet));

assert(corrupted_tcp_checksum != saved_tcp_checksum);

data_packet[40] ^= 0x01;

assert(tcp_checksum(
    data_packet, sizeof(data_packet)
) == saved_tcp_checksum);

write16(data_packet + 36, saved_tcp_checksum);
    printf("All packet pipeline tests passed\n");

    return 0;
}
