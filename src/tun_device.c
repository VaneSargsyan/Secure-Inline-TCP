
#include "tun_device.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int tun_open(const char *name) {
    if (name == NULL || name[0] == '\0' ||
        strlen(name) >= IFNAMSIZ) {
        errno = EINVAL;
        return -1;
    }

    int fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    memcpy(ifr.ifr_name, name, strlen(name) + 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    return fd;
}

ssize_t tun_read_packet(
    int fd,
    unsigned char *buffer,
    size_t capacity
) {
    if (fd < 0 || buffer == NULL || capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    return read(fd, buffer, capacity);
}

ssize_t tun_write_packet(
    int fd,
    const unsigned char *packet,
    size_t length
) {
    if (fd < 0 || packet == NULL || length == 0) {
        errno = EINVAL;
        return -1;
    }

    return write(fd, packet, length);
}
