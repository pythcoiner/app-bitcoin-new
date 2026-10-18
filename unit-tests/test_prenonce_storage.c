#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "crypto.h"
#include "prenonce_storage.h"

#define RECORD_SIZE sizeof(prenonce_record_t)

// what is left after the cut point of a torn write
typedef enum {
    TEAR_KEEP_OLD,
    TEAR_FILL_00,
    TEAR_FILL_FF,
    N_TEAR_MODES,
} tear_mode_t;

// byte offset at which the next nvm_write is cut, or -1 to complete it
static int tear_at = -1;
static tear_mode_t tear_mode;

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    if (tear_at < 0 || (unsigned int) tear_at >= src_len) {
        memcpy(dst_adr, src_adr, src_len);
        return;
    }
    memcpy(dst_adr, src_adr, tear_at);
    uint8_t *rest = (uint8_t *) dst_adr + tear_at;
    if (tear_mode == TEAR_FILL_00) {
        memset(rest, 0x00, src_len - tear_at);
    } else if (tear_mode == TEAR_FILL_FF) {
        memset(rest, 0xFF, src_len - tear_at);
    }
    tear_at = -1;
}

static void reset_slots(void) {
    memset(N_prenonce_slots_real, 0, sizeof(N_prenonce_slots_real));
    tear_at = -1;
}

static void assert_loaded(const prenonce_state_t *expected) {
    prenonce_state_t loaded;
    assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_OK);
    assert_memory_equal(&loaded, expected, sizeof(loaded));
}

// stores state with j consumed, and checks that it is loaded back
static void store_consumed(prenonce_state_t *state, uint32_t j) {
    assert_true(prenonce_window_consume(&state->window, j));
    assert_true(prenonce_storage_store(state));
    assert_loaded(state);
}

static void test_empty(void **state) {
    (void) state;
    reset_slots();

    prenonce_state_t loaded;
    assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_EMPTY);
    prenonce_state_t s = {0};
    assert_false(prenonce_storage_store(&s));
    assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_EMPTY);

    prenonce_state_t created;
    assert_true(prenonce_storage_load_or_init(&created));
    assert_int_equal(created.epoch, 0);
    assert_int_equal(created.window.hwm, 0);
    assert_true(prenonce_window_is_canonical(&created.window));
    assert_false(is_array_all_zeros(created.nonce_init, sizeof(created.nonce_init)));
    assert_loaded(&created);

    // a second call loads the same state
    prenonce_state_t again;
    assert_true(prenonce_storage_load_or_init(&again));
    assert_memory_equal(&again, &created, sizeof(again));
}

static void test_non_canonical_refused(void **state) {
    (void) state;
    reset_slots();

    prenonce_state_t s;
    assert_true(prenonce_storage_load_or_init(&s));
    prenonce_state_t bad = s;
    bitvector_set(bad.window.consumed, 0, true);
    assert_false(prenonce_storage_store(&bad));
    assert_loaded(&s);
}

static void test_lazy_init_torn(void **state) {
    (void) state;

    for (int mode = 0; mode < N_TEAR_MODES; mode++) {
        for (int k = 0; k < (int) RECORD_SIZE; k++) {
            reset_slots();
            tear_mode = mode;
            tear_at = k;
            prenonce_state_t created;
            if (prenonce_storage_load_or_init(&created)) {
                // the cut left the same bytes as a complete write
                assert_loaded(&created);
            } else {
                prenonce_state_t loaded;
                assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_EMPTY);
            }

            // initialization is retried
            assert_true(prenonce_storage_load_or_init(&created));
            assert_loaded(&created);
        }
    }
}

// Cuts at every byte the write of the record that follows `n_stores` stores; the record before
// stays in force unless the write completed.
static void check_store_torn(unsigned int n_stores) {
    reset_slots();
    prenonce_state_t old;
    assert_true(prenonce_storage_load_or_init(&old));
    for (unsigned int i = 0; i < n_stores; i++) {
        store_consumed(&old, 2 * i);
    }
    prenonce_slot_t snapshot[PRENONCE_N_SLOTS];
    memcpy(snapshot, N_prenonce_slots_real, sizeof(snapshot));

    prenonce_state_t new = old;
    assert_true(prenonce_window_consume(&new.window, 100));

    for (int mode = 0; mode < N_TEAR_MODES; mode++) {
        for (int k = 0; k < (int) RECORD_SIZE; k++) {
            memcpy(N_prenonce_slots_real, snapshot, sizeof(snapshot));
            tear_mode = mode;
            tear_at = k;
            if (prenonce_storage_store(&new)) {
                assert_loaded(&new);
            } else {
                assert_loaded(&old);
            }

            // the next store wins over both slots
            prenonce_state_t next = new;
            store_consumed(&next, 101);
        }
    }
}

static void test_store_torn(void **state) {
    (void) state;

    // the cut write goes to slot 1, then to slot 0
    check_store_torn(2);
    check_store_torn(3);
}

static void test_regenerate_torn(void **state) {
    (void) state;

    reset_slots();
    prenonce_state_t old;
    assert_true(prenonce_storage_load_or_init(&old));
    store_consumed(&old, 3);
    prenonce_slot_t snapshot[PRENONCE_N_SLOTS];
    memcpy(snapshot, N_prenonce_slots_real, sizeof(snapshot));

    for (int mode = 0; mode < N_TEAR_MODES; mode++) {
        for (int k = 0; k < (int) RECORD_SIZE; k++) {
            memcpy(N_prenonce_slots_real, snapshot, sizeof(snapshot));
            tear_mode = mode;
            tear_at = k;
            bool ok = prenonce_storage_regenerate();

            prenonce_state_t loaded;
            assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_OK);
            if (ok) {
                assert_int_equal(loaded.epoch, old.epoch + 1);
                assert_int_equal(loaded.window.hwm, 0);
                assert_true(prenonce_window_is_canonical(&loaded.window));
                assert_memory_not_equal(loaded.nonce_init, old.nonce_init, sizeof(old.nonce_init));
            } else {
                assert_memory_equal(&loaded, &old, sizeof(old));
            }

            // seq continues across the regeneration: the next store wins over both slots
            store_consumed(&loaded, 50);
        }
    }

    // a complete regeneration
    memcpy(N_prenonce_slots_real, snapshot, sizeof(snapshot));
    assert_true(prenonce_storage_regenerate());
    prenonce_state_t regenerated;
    assert_int_equal(prenonce_storage_load(&regenerated), PRENONCE_STORAGE_OK);
    assert_int_equal(regenerated.epoch, old.epoch + 1);
    assert_true(prenonce_window_check(&regenerated.window, 0));
    store_consumed(&regenerated, 0);
}

static void test_equal_seq_corrupt(void **state) {
    (void) state;

    // a and b are both written with seq 1 to slot 1, from the same initial record
    reset_slots();
    prenonce_state_t initial;
    assert_true(prenonce_storage_load_or_init(&initial));
    prenonce_slot_t after_init[PRENONCE_N_SLOTS];
    memcpy(after_init, N_prenonce_slots_real, sizeof(after_init));

    prenonce_state_t a = initial;
    store_consumed(&a, 1);
    prenonce_slot_t record_a = N_prenonce_slots_real[1];

    memcpy(N_prenonce_slots_real, after_init, sizeof(after_init));
    prenonce_state_t b = initial;
    store_consumed(&b, 2);

    // a is placed in slot 0, next to b
    N_prenonce_slots_real[0] = record_a;
    prenonce_state_t loaded;
    assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_CORRUPT);
    assert_false(prenonce_storage_load_or_init(&loaded));
    assert_false(prenonce_storage_store(&b));

    // regeneration recovers
    assert_true(prenonce_storage_regenerate());
    assert_int_equal(prenonce_storage_load(&loaded), PRENONCE_STORAGE_OK);
    assert_int_equal(loaded.epoch, 1);
    assert_int_equal(loaded.window.hwm, 0);
    assert_memory_not_equal(loaded.nonce_init, initial.nonce_init, sizeof(initial.nonce_init));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty),
        cmocka_unit_test(test_non_canonical_refused),
        cmocka_unit_test(test_lazy_init_torn),
        cmocka_unit_test(test_store_torn),
        cmocka_unit_test(test_regenerate_torn),
        cmocka_unit_test(test_equal_seq_corrupt),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
