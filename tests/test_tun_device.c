
#include "tun_device.h"

#include <stdio.h>
#include <unistd.h>

int main(void) {
    int fd = tun_open("tun-test");

    if (fd < 0) {
        perror("tun_open");
        return 1;
    }

    printf("TUN interface opened successfully\n");

    close(fd);

    printf("TUN interface closed successfully\n");

    return 0;
}
