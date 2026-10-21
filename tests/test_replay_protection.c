
#include "replay_protection.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
    ReplayWindow window = {0};

    assert(replay_accept(&window, 100) == 1);
    assert(replay_accept(&window, 100) == 0);

    assert(replay_accept(&window, 102) == 1);
    assert(replay_accept(&window, 101) == 1);
    assert(replay_accept(&window, 101) == 0);

    assert(replay_accept(&window, 200) == 1);
    assert(replay_accept(&window, 100) == 0);

    assert(replay_check(&window, 201) == 1);
    assert(replay_accept(&window, 201) == 1);
    assert(replay_accept(&window, 201) == 0);

    printf("All replay protection tests passed\n");
    return 0;
}
