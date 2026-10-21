
#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stddef.h>
#include <stdint.h>

#define REPLAY_WINDOW_SIZE 64

typedef struct {
    uint64_t highest;
    uint64_t bitmap;
    int initialized;
} ReplayWindow;

int replay_check(const ReplayWindow *window, uint64_t sequence);
int replay_accept(ReplayWindow *window, uint64_t sequence);

#endif
