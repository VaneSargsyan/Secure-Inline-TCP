
#include "replay_protection.h"

int replay_check(const ReplayWindow *window, uint64_t sequence) {
    if (window == NULL) {
        return 0;
    }

    if (!window->initialized || sequence > window->highest) {
        return 1;
    }

    uint64_t difference = window->highest - sequence;

    if (difference >= REPLAY_WINDOW_SIZE) {
        return 0;
    }

    return (window->bitmap & (UINT64_C(1) << difference)) == 0;
}

int replay_accept(ReplayWindow *window, uint64_t sequence) {
    if (!replay_check(window, sequence)) {
        return 0;
    }

    if (!window->initialized) {
        window->highest = sequence;
        window->bitmap = 1;
        window->initialized = 1;
        return 1;
    }

    if (sequence > window->highest) {
        uint64_t shift = sequence - window->highest;

        if (shift >= REPLAY_WINDOW_SIZE) {
            window->bitmap = 1;
        } else {
            window->bitmap = (window->bitmap << shift) | 1;
        }

        window->highest = sequence;
        return 1;
    }

    uint64_t difference = window->highest - sequence;
    window->bitmap |= UINT64_C(1) << difference;

    return 1;
}
