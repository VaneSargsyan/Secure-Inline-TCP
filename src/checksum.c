#include "checksum.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

static uint32_t checksum_add(
    uint32_t sum,
    const uint8_t *data,
    size_t length
) {
    while (length >= 2) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }

    if (length == 1) {
        sum += (uint16_t)data[0] << 8;
    }

    return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t ipv4_checksum(const void *data, size_t length) {
    uint32_t sum = checksum_add(0, data, length);
    return htons(checksum_finish(sum));
}

uint16_t tcp_checksum(
    const uint8_t *packet,
    size_t packet_length
) {
    if (packet == NULL || packet_length < sizeof(struct iphdr)) {
        return 0;
    }

    const struct iphdr *ip = (const struct iphdr *)packet;

    size_t ip_header_length = (size_t)ip->ihl * 4;
    size_t total_length = ntohs(ip->tot_len);

    if (ip->version != 4 ||
        ip->protocol != IPPROTO_TCP ||
        ip_header_length < sizeof(struct iphdr) ||
        total_length < ip_header_length + sizeof(struct tcphdr) ||
        total_length > packet_length) {
        return 0;
    }

    const uint8_t *tcp = packet + ip_header_length;
    size_t tcp_length = total_length - ip_header_length;

    uint32_t sum = 0;

    sum = checksum_add(sum, packet + 12, 8);

    uint8_t pseudo_header[4] = {
        0,
        IPPROTO_TCP,
        (uint8_t)(tcp_length >> 8),
        (uint8_t)tcp_length
    };

    sum = checksum_add(sum, pseudo_header, sizeof(pseudo_header));
    sum = checksum_add(sum, tcp, tcp_length);

    return htons(checksum_finish(sum));
}
