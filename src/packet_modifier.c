#include "checksum.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include "packet_parser.h"
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static int packet_callback(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *packet,
    void *data
) {
    (void)message;
    (void)data;

    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(packet);

    if (!header) {
        return -1;
    }

    uint32_t id = ntohl(header->packet_id);
    unsigned char *payload = NULL;
    int length = nfq_get_payload(packet, &payload);

    ParsedPacket parsed;

if (length > 0 &&
    parse_tcp_packet(payload, (size_t)length, &parsed)) {
    struct in_addr src = {.s_addr = parsed.source_ip};
    struct in_addr dst = {.s_addr = parsed.destination_ip};

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip)) &&
        inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip))) {
        printf("Packet ID: %u\n", id);
        printf("Source: %s:%u\n", src_ip, parsed.source_port);
        printf("Destination: %s:%u\n", dst_ip, parsed.destination_port);
        printf("TCP Payload: %zu bytes\n", parsed.payload_len);
uint8_t packet_copy[65536];

if ((size_t)length <= sizeof(packet_copy)) {
    memcpy(packet_copy, payload, (size_t)length);

    struct iphdr *ip = (struct iphdr *)packet_copy;
    size_t ip_header_length = (size_t)ip->ihl * 4;

    struct tcphdr *tcp =
        (struct tcphdr *)(packet_copy + ip_header_length);

    uint16_t original_checksum = ntohs(tcp->check);

    tcp->check = 0;

    uint16_t calculated_checksum = ntohs(
        tcp_checksum(packet_copy, (size_t)length)
    );

    printf("TCP checksum (packet): 0x%04x\n", original_checksum);
    printf("TCP checksum (calculated): 0x%04x\n", calculated_checksum);
}
        fflush(stdout);

    }
}
if (length > 0 &&
    parse_tcp_packet(payload, (size_t)length, &parsed) &&
    parsed.payload_len > 0) {

    size_t offset = (size_t)(parsed.payload - payload);

    if (payload[offset] == 'G') {
        payload[offset] = 'H';

        struct iphdr *ip = (struct iphdr *)payload;
        struct tcphdr *tcp =
            (struct tcphdr *)(payload + ip->ihl * 4);

        tcp->check = 0;
        tcp->check = tcp_checksum(payload, (size_t)length);

        return nfq_set_verdict(
            queue, id, NF_ACCEPT, (uint32_t)length, payload
        );
    }
}

    return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}

int main(void) {
    struct nfq_handle *handle = nfq_open();

    if (!handle) {
        fprintf(stderr, "Cannot open NFQUEUE\n");
        return EXIT_FAILURE;
    }

    struct nfq_q_handle *queue = nfq_create_queue(
        handle, 0, &packet_callback, NULL
    );

    if (!queue) {
        fprintf(stderr, "Cannot create queue\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Cannot set copy mode\n");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    int fd = nfq_fd(handle);
    char buffer[65536] __attribute__((aligned));

    while (1) {
        int received = recv(fd, buffer, sizeof(buffer), 0);

        if (received >= 0) {
            nfq_handle_packet(handle, buffer, received);
        } else {
            perror("recv");
            break;
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return EXIT_SUCCESS;
}
