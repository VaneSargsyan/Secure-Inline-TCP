
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(9000);
    inet_pton(AF_INET, "10.0.2.2", &address.sin_addr);

    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        close(fd);
        return 1;
    }

    char buffer[2048];

    printf("Device2 waiting for UDP packet...\n");
    fflush(stdout);

    ssize_t received = recvfrom(
        fd, buffer, sizeof(buffer) - 1, 0, NULL, NULL
    );

    if (received < 0) {
        perror("recvfrom");
        close(fd);
        return 1;
    }

    buffer[received] = '\0';
    printf("Received: %s\n", buffer);

    close(fd);
    return 0;
}
