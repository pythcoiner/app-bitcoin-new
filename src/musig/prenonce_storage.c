#ifdef HAVE_MUSIG2_PRENONCES

#include <stddef.h>
#include <string.h>

#include "prenonce_storage.h"

/* Local headers */
#include "crypto.h"

#define PRENONCE_RECORD_MAGIC   0x4d32504e  // "M2PN"
#define PRENONCE_RECORD_VERSION 1

static const uint8_t prenonce_record_tag[] = {'M', 'u', 'S', 'i', 'g', '2', 'P', 'r', 'e', 'n',
                                              'o', 'n', 'c', 'e', 'R', 'e', 'c', 'o', 'r', 'd'};

_Static_assert(sizeof(prenonce_record_t) <= PRENONCE_SLOT_SIZE, "record larger than its slot");

#ifndef SKIP_FOR_CMOCKA
// Initialized to all zeros, that is with no valid record.
const prenonce_slot_t N_prenonce_slots_real[PRENONCE_N_SLOTS];
#define N_prenonce_slots ((const volatile prenonce_slot_t *) PIC(N_prenonce_slots_real))
#else
prenonce_slot_t N_prenonce_slots_real[PRENONCE_N_SLOTS];
#define N_prenonce_slots N_prenonce_slots_real
#endif

static void compute_checksum(const prenonce_record_t *record, uint8_t out[static 32]) {
    crypto_tr_tagged_hash(prenonce_record_tag,
                          sizeof(prenonce_record_tag),
                          (const uint8_t *) record,
                          offsetof(prenonce_record_t, checksum),
                          NULL,
                          0,
                          out);
}

// reads the record in the given slot, and returns true if it is valid
static bool read_slot(unsigned int slot, prenonce_record_t *record) {
    memcpy(record, (const void *) &N_prenonce_slots[slot].record, sizeof(*record));

    uint8_t checksum[32];
    compute_checksum(record, checksum);
    return record->magic == PRENONCE_RECORD_MAGIC && record->version == PRENONCE_RECORD_VERSION &&
           record->window_bits == PRENONCE_WINDOW_SIZE &&
           memcmp(checksum, record->checksum, sizeof(checksum)) == 0 &&
           prenonce_window_is_canonical(&record->state.window);
}

// Finds the valid record with the highest seq. On PRENONCE_STORAGE_CORRUPT, returns the record of
// slot 0, so that regeneration can write past it.
static prenonce_storage_status_t find_current(prenonce_record_t *current,
                                              unsigned int *current_slot) {
    prenonce_record_t records[PRENONCE_N_SLOTS];
    bool valid[PRENONCE_N_SLOTS];
    for (unsigned int i = 0; i < PRENONCE_N_SLOTS; i++) {
        valid[i] = read_slot(i, &records[i]);
    }

    prenonce_storage_status_t status = PRENONCE_STORAGE_OK;
    if (valid[0] && valid[1]) {
        if (records[0].seq == records[1].seq &&
            memcmp(&records[0], &records[1], sizeof(records[0])) != 0) {
            status = PRENONCE_STORAGE_CORRUPT;
            *current_slot = 0;
        } else {
            *current_slot = records[0].seq >= records[1].seq ? 0 : 1;
        }
    } else if (valid[0] || valid[1]) {
        *current_slot = valid[0] ? 0 : 1;
    } else {
        status = PRENONCE_STORAGE_EMPTY;
    }

    if (status != PRENONCE_STORAGE_EMPTY) {
        memcpy(current, &records[*current_slot], sizeof(*current));
    }
    explicit_bzero(records, sizeof(records));
    return status;
}

// writes state with the given seq to the given slot, then reads it back
static bool write_slot(unsigned int slot, uint32_t seq, const prenonce_state_t *state) {
    prenonce_record_t record = {.magic = PRENONCE_RECORD_MAGIC,
                                .version = PRENONCE_RECORD_VERSION,
                                .window_bits = PRENONCE_WINDOW_SIZE,
                                .seq = seq};
    memcpy(&record.state, state, sizeof(record.state));
    compute_checksum(&record, record.checksum);

    nvm_write((void *) &N_prenonce_slots[slot].record, &record, sizeof(record));

    bool ok = memcmp((const void *) &N_prenonce_slots[slot].record, &record, sizeof(record)) == 0;
    explicit_bzero(&record, sizeof(record));
    if (!ok) {
        PRINTF("Pre-nonce record read back failed\n");
    }
    return ok;
}

// writes state to the slot that does not hold current, with the next seq
static bool write_after(const prenonce_record_t *current,
                        unsigned int current_slot,
                        const prenonce_state_t *state) {
    if (current->seq == UINT32_MAX) {
        PRINTF("Pre-nonce record seq exhausted\n");
        return false;
    }
    return write_slot(1 - current_slot, current->seq + 1, state);
}

// fills state with a fresh nonce_init and an empty window
static bool fresh_state(uint32_t epoch, prenonce_state_t *state) {
    memset(state, 0, sizeof(*state));
    state->epoch = epoch;
    return cx_get_random_bytes(state->nonce_init, sizeof(state->nonce_init)) == CX_OK;
}

prenonce_storage_status_t prenonce_storage_load(prenonce_state_t *state) {
    prenonce_record_t current;
    unsigned int current_slot;
    prenonce_storage_status_t status = find_current(&current, &current_slot);
    if (status == PRENONCE_STORAGE_OK) {
        memcpy(state, &current.state, sizeof(*state));
    }
    explicit_bzero(&current, sizeof(current));
    return status;
}

bool prenonce_storage_load_or_init(prenonce_state_t *state) {
    prenonce_storage_status_t status = prenonce_storage_load(state);
    if (status != PRENONCE_STORAGE_EMPTY) {
        return status == PRENONCE_STORAGE_OK;
    }

    if (!fresh_state(0, state) || !write_slot(0, 0, state)) {
        explicit_bzero(state, sizeof(*state));
        return false;
    }
    return true;
}

bool prenonce_storage_store(const prenonce_state_t *state) {
    if (!prenonce_window_is_canonical(&state->window)) {
        return false;
    }

    prenonce_record_t current;
    unsigned int current_slot;
    bool ok = find_current(&current, &current_slot) == PRENONCE_STORAGE_OK &&
              write_after(&current, current_slot, state);
    explicit_bzero(&current, sizeof(current));
    return ok;
}

bool prenonce_storage_regenerate(void) {
    prenonce_record_t current;
    unsigned int current_slot;
    prenonce_storage_status_t status = find_current(&current, &current_slot);

    prenonce_state_t state;
    bool ok;
    if (status == PRENONCE_STORAGE_EMPTY) {
        ok = fresh_state(0, &state) && write_slot(0, 0, &state);
    } else {
        ok = fresh_state(current.state.epoch + 1, &state) &&
             write_after(&current, current_slot, &state);
    }
    explicit_bzero(&current, sizeof(current));
    explicit_bzero(&state, sizeof(state));
    return ok;
}

#endif  // HAVE_MUSIG2_PRENONCES
