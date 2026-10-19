
#include "packet_parser.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int parse_tcp_packet(
    const unsigned char *packet,
    size_t packet_len,
    ParsedPacket *result
) {
    if (!packet || !result || packet_len < sizeof(struct iphdr)) {
        return 0;
    }

    memset(result, 0, sizeof(*result));

    const struct iphdr *ip = (const struct iphdr *)packet;

    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) {
        return 0;
    }

    size_t ip_len = (size_t)ip->ihl * 4;

    if (ip_len < sizeof(struct iphdr) ||
        ip_len > packet_len) {
        return 0;
    }

    size_t total_len = ntohs(ip->tot_len);

    if (total_len < ip_len + sizeof(struct tcphdr) ||
        total_len > packet_len) {
        return 0;
    }

    if ((ntohs(ip->frag_off) & 0x3FFF) != 0) {
        return 0;
    }

    const struct tcphdr *tcp =
        (const struct tcphdr *)(packet + ip_len);

    size_t tcp_len = (size_t)tcp->doff * 4;

    if (tcp_len < sizeof(struct tcphdr) ||
        tcp_len > total_len - ip_len) {
        return 0;
    }

    result->ip_header = packet;
    result->ip_header_len = ip_len;

    result->tcp_header = packet + ip_len;
    result->tcp_header_len = tcp_len;

    result->payload = packet + ip_len + tcp_len;
    result->payload_len = total_len - ip_len - tcp_len;

    result->source_ip = ip->saddr;
    result->destination_ip = ip->daddr;

    result->source_port = ntohs(tcp->source);
    result->destination_port = ntohs(tcp->dest);

    return 1;
}
