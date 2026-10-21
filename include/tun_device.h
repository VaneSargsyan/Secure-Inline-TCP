
#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H

#include <stddef.h>
#include <sys/types.h>

int tun_open(const char *name);
ssize_t tun_read_packet(int fd, unsigned char *buffer, size_t capacity);
ssize_t tun_write_packet(int fd, const unsigned char *packet, size_t length);

#endif
