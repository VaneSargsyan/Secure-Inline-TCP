
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "packet_parser.h"

int main(void) {
    unsigned char packet[128] = {0};
    const char message[] = "Hello TCP";
    size_t payload_len = sizeof(message) - 1;
    size_t total_len = 20 + 20 + payload_len;

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons((uint16_t)total_len);
    ip->saddr = inet_addr("10.0.1.1");
    ip->daddr = inet_addr("10.0.3.2");

    struct tcphdr *tcp = (struct tcphdr *)(packet + 20);
    tcp->doff = 5;
    tcp->source = htons(12345);
    tcp->dest = htons(5000);

    memcpy(packet + 40, message, payload_len);

    ParsedPacket parsed;

    if (!parse_tcp_packet(packet, total_len, &parsed)) {
        fprintf(stderr, "ERROR: Valid TCP packet rejected!\n");
        return 1;
    }

    printf("SUCCESS: TCP packet parsed!\n");

    if (parsed.ip_header_len != 20 ||
        parsed.tcp_header_len != 20 ||
        parsed.payload_len != payload_len ||
        parsed.source_port != 12345 ||
        parsed.destination_port != 5000) {
                fprintf(stderr, "ERROR: Truncated packet accepted!\n");
        return 1;
    }

    printf("SUCCESS: Truncated packet rejected!\n");

    return 0;
}
