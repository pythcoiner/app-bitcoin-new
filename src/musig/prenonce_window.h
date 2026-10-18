#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Local headers */
#include "bitvector.h"

/**
 * Tracks which pre-nonce indices j were consumed by a signing. Each j can be consumed only once:
 * every j below the high-water mark hwm is consumed, each of the PRENONCE_WINDOW_SIZE j starting
 * at hwm is consumed if its bit is set, and any j above them is refused until hwm moves forward.
 */

// number of j that can be outstanding at once, above hwm
#define PRENONCE_WINDOW_SIZE 128

// j must be below this value; hwm reaching it means that all the j are consumed
#define PRENONCE_J_END UINT32_MAX

typedef struct {
    uint32_t hwm;
    // bit i is set if j = hwm + i is consumed
    uint8_t consumed[BITVECTOR_REAL_SIZE(PRENONCE_WINDOW_SIZE)];
} prenonce_window_t;

/**
 * Returns true if the window is in its canonical form: the bit of hwm is clear (consume and
 * advance always move hwm past the consumed j), and no bit is set for a j at or above
 * PRENONCE_J_END.
 */
bool prenonce_window_is_canonical(const prenonce_window_t *window);

/**
 * Returns true if j can be consumed.
 */
bool prenonce_window_check(const prenonce_window_t *window, uint32_t j);

/**
 * Marks j as consumed, then moves hwm past the consumed j that follow it.
 *
 * @return true on success, false if j cannot be consumed; the window is unchanged in that case.
 */
bool prenonce_window_consume(prenonce_window_t *window, uint32_t j);

/**
 * Sets hwm to the maximum of hwm and new_hwm, marking all the j below new_hwm as consumed.
 */
void prenonce_window_advance(prenonce_window_t *window, uint32_t new_hwm);
