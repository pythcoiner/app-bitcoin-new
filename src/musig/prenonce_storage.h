#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Local headers */
#include "prenonce_window.h"

/**
 * Persistent state of the pre-nonces. It is kept as a record in two NVRAM slots: each write goes
 * to the slot that does not hold the current record, with a higher seq, and is read back before
 * it is considered done. A write interrupted at any point leaves the previous record in force.
 *
 * Like all the NVRAM data, the state is wiped on app or OS update; nonce_init and the window are
 * lost together.
 */

#define PRENONCE_NONCE_INIT_SIZE 32

// must be at least the NVRAM page size of all the targets, so that each slot has its own pages
#define PRENONCE_SLOT_SIZE 512

typedef struct {
    // incremented each time nonce_init is regenerated
    uint32_t epoch;
    prenonce_window_t window;
    uint8_t nonce_init[PRENONCE_NONCE_INIT_SIZE];
} prenonce_state_t;

typedef enum {
    PRENONCE_STORAGE_OK,
    // no record was ever written
    PRENONCE_STORAGE_EMPTY,
    // the two slots hold different records with the same seq
    PRENONCE_STORAGE_CORRUPT,
} prenonce_storage_status_t;

// Members are private and must not be accessed outside of prenonce_storage.c.
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t window_bits;
    uint32_t seq;
    prenonce_state_t state;
    uint8_t checksum[32];
} prenonce_record_t;

typedef struct {
    prenonce_record_t record;
} __attribute__((aligned(PRENONCE_SLOT_SIZE))) prenonce_slot_t;

#define PRENONCE_N_SLOTS 2

#ifdef SKIP_FOR_CMOCKA
// in unit tests the slots are in RAM, and nvm_write is provided by the test
extern prenonce_slot_t N_prenonce_slots_real[PRENONCE_N_SLOTS];
#endif

/**
 * Loads the current state.
 *
 * @return PRENONCE_STORAGE_OK if state was filled; otherwise state is left untouched.
 */
prenonce_storage_status_t prenonce_storage_load(prenonce_state_t *state);

/**
 * Loads the current state, creating it with a fresh nonce_init and an empty window if no record
 * was ever written.
 *
 * @return true on success, false if the storage is corrupt or the write failed.
 */
bool prenonce_storage_load_or_init(prenonce_state_t *state);

/**
 * Writes state as the new record.
 *
 * @return true once the new record is read back, false otherwise. On failure, the previous record
 * may still be in force.
 */
bool prenonce_storage_store(const prenonce_state_t *state);

/**
 * Replaces nonce_init with a fresh one, increments the epoch and empties the window. It also
 * recovers a corrupt storage.
 *
 * @return true once the new record is read back, false otherwise.
 */
bool prenonce_storage_regenerate(void);
