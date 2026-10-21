
#include "tun_device.h"

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    int fd = tun_open(argv[1]);

    if (fd < 0) {
        perror("tun_open");
        return 1;
    }

    printf("TUN interface %s opened successfully\n", argv[1]);
    printf("Waiting for IP packets...\n");
    fflush(stdout);

    unsigned char packet[65535];

    while (1) {
        ssize_t length = tun_read_packet(
            fd, packet, sizeof(packet)
        );

        if (length < 0) {
            perror("tun_read_packet");
            close(fd);
            return 1;
        }

        printf("Received IP packet: %zd bytes\n", length);
        fflush(stdout);
    }
}
