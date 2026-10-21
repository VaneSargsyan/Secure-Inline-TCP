
#include "tun_device.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    int fd = tun_open("tun-test");

    if (fd < 0) {
        perror("tun_open");
        return 1;
    }

    unsigned char packet[65535];

    printf("Waiting for IP packet...\n");
    fflush(stdout);

    ssize_t length = tun_read_packet(
        fd, packet, sizeof(packet)
    );

    if (length < 0) {
        perror("tun_read_packet");
        close(fd);
        return 1;
    }

    printf("Received %zd bytes\n", length);
printf("IP version: %u\n", (unsigned int)(packet[0] >> 4));

printf("First bytes: ");
for (ssize_t i = 0; i < length && i < 20; i++) {
    printf("%02x ", packet[i]);
}
printf("\n");

    if (length >= 20 && (packet[0] >> 4) == 4) {
        char source[INET_ADDRSTRLEN];
        char destination[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, packet + 12, source, sizeof(source));
        inet_ntop(AF_INET, packet + 16, destination, sizeof(destination));

        printf("Source: %s\n", source);
        printf("Destination: %s\n", destination);
        printf("Protocol: %u\n", (unsigned int)packet[9]);
    }

    close(fd);
    return 0;
}
