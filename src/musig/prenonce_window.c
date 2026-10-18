#include "prenonce_window.h"

static bool is_consumed(const prenonce_window_t *window, unsigned int i) {
    return bitvector_get(window->consumed, i);
}

// moves the bits of the window down by n positions, with n at most PRENONCE_WINDOW_SIZE
static void shift_window(prenonce_window_t *window, unsigned int n) {
    for (unsigned int i = 0; i < PRENONCE_WINDOW_SIZE; i++) {
        bool value = i + n < PRENONCE_WINDOW_SIZE && is_consumed(window, i + n);
        bitvector_set(window->consumed, i, value);
    }
}

// moves hwm past the run of consumed j starting at hwm
static void skip_consumed(prenonce_window_t *window) {
    unsigned int n = 0;
    while (n < PRENONCE_WINDOW_SIZE && is_consumed(window, n)) {
        n++;
    }
    shift_window(window, n);
    window->hwm += n;
}

bool prenonce_window_is_canonical(const prenonce_window_t *window) {
    if (is_consumed(window, 0)) {
        return false;
    }
    for (unsigned int i = 0; i < PRENONCE_WINDOW_SIZE; i++) {
        if ((uint64_t) window->hwm + i >= PRENONCE_J_END && is_consumed(window, i)) {
            return false;
        }
    }
    return true;
}

bool prenonce_window_check(const prenonce_window_t *window, uint32_t j) {
    if (j < window->hwm || j >= PRENONCE_J_END ||
        (uint64_t) j >= (uint64_t) window->hwm + PRENONCE_WINDOW_SIZE) {
        return false;
    }
    return !is_consumed(window, j - window->hwm);
}

bool prenonce_window_consume(prenonce_window_t *window, uint32_t j) {
    if (!prenonce_window_check(window, j)) {
        return false;
    }
    bitvector_set(window->consumed, j - window->hwm, true);
    skip_consumed(window);
    return true;
}

void prenonce_window_advance(prenonce_window_t *window, uint32_t new_hwm) {
    if (new_hwm <= window->hwm) {
        return;
    }
    uint32_t n = new_hwm - window->hwm;
    shift_window(window, n < PRENONCE_WINDOW_SIZE ? n : PRENONCE_WINDOW_SIZE);
    window->hwm = new_hwm;
    skip_consumed(window);
}
