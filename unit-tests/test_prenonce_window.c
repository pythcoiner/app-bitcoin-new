#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "prenonce_window.h"

static void assert_window_empty(const prenonce_window_t *window) {
    for (unsigned int i = 0; i < sizeof(window->consumed); i++) {
        assert_int_equal(window->consumed[i], 0);
    }
}

// consumes j and checks that the call fails and leaves the window unchanged
static void assert_consume_refused(prenonce_window_t *window, uint32_t j) {
    prenonce_window_t before = *window;
    assert_false(prenonce_window_check(window, j));
    assert_false(prenonce_window_consume(window, j));
    assert_memory_equal(window, &before, sizeof(before));
}

static void test_fresh_window(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    assert_true(prenonce_window_is_canonical(&window));
    assert_true(prenonce_window_check(&window, 0));
    assert_true(prenonce_window_check(&window, 127));
    assert_consume_refused(&window, 128);
}

// consumes n + 1 and 1..n-1 first, then 0, so that hwm moves by n at once; the bit of n + 1 must
// survive the shift
static void check_shift(uint32_t n) {
    prenonce_window_t window = {0};
    if (n + 1 < PRENONCE_WINDOW_SIZE) {
        assert_true(prenonce_window_consume(&window, n + 1));
    }
    for (uint32_t j = 1; j < n; j++) {
        assert_true(prenonce_window_consume(&window, j));
        assert_int_equal(window.hwm, 0);
    }
    assert_true(prenonce_window_consume(&window, 0));

    assert_int_equal(window.hwm, n);
    assert_true(prenonce_window_is_canonical(&window));
    assert_true(prenonce_window_check(&window, n));
    if (n + 1 < PRENONCE_WINDOW_SIZE) {
        assert_consume_refused(&window, n + 1);
        assert_true(prenonce_window_check(&window, n + 2));
    } else {
        assert_window_empty(&window);
    }
    for (uint32_t j = 0; j < n; j++) {
        assert_consume_refused(&window, j);
    }
}

static void test_shift(void **state) {
    (void) state;

    const uint32_t shifts[] = {1, 7, 8, 9, 64, 127, 128};
    for (size_t i = 0; i < sizeof(shifts) / sizeof(shifts[0]); i++) {
        check_shift(shifts[i]);
    }
}

static void test_full_window(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    for (uint32_t j = 1; j < PRENONCE_WINDOW_SIZE; j++) {
        assert_true(prenonce_window_consume(&window, j));
    }
    assert_int_equal(window.hwm, 0);
    for (uint32_t j = 1; j < PRENONCE_WINDOW_SIZE; j++) {
        assert_consume_refused(&window, j);
    }
    assert_consume_refused(&window, PRENONCE_WINDOW_SIZE);

    assert_true(prenonce_window_consume(&window, 0));
    assert_int_equal(window.hwm, PRENONCE_WINDOW_SIZE);
    assert_window_empty(&window);
    assert_true(prenonce_window_check(&window, 2 * PRENONCE_WINDOW_SIZE - 1));
    assert_consume_refused(&window, 2 * PRENONCE_WINDOW_SIZE);
}

static void test_below_hwm(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    prenonce_window_advance(&window, 1000);
    assert_consume_refused(&window, 0);
    assert_consume_refused(&window, 999);
    assert_true(prenonce_window_consume(&window, 1000));
    assert_int_equal(window.hwm, 1001);
    assert_consume_refused(&window, 1000);
}

static void test_beyond_window(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    prenonce_window_advance(&window, 1000);
    assert_true(prenonce_window_check(&window, 1000 + PRENONCE_WINDOW_SIZE - 1));
    assert_consume_refused(&window, 1000 + PRENONCE_WINDOW_SIZE);
    assert_consume_refused(&window, UINT32_MAX - 1);
}

static void test_consumed(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    assert_true(prenonce_window_consume(&window, 5));
    assert_int_equal(window.hwm, 0);
    assert_consume_refused(&window, 5);
    assert_true(prenonce_window_check(&window, 4));
    assert_true(prenonce_window_check(&window, 6));
}

static void test_advance(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    assert_true(prenonce_window_consume(&window, 3));
    assert_true(prenonce_window_consume(&window, 10));

    // the consumed j above new_hwm stay consumed
    prenonce_window_advance(&window, 5);
    assert_int_equal(window.hwm, 5);
    assert_true(prenonce_window_is_canonical(&window));
    assert_consume_refused(&window, 3);
    assert_consume_refused(&window, 10);
    assert_true(prenonce_window_check(&window, 9));

    // advancing below hwm does nothing
    prenonce_window_t before = window;
    prenonce_window_advance(&window, 2);
    assert_memory_equal(&window, &before, sizeof(before));

    // hwm moves past the consumed j at new_hwm
    prenonce_window_advance(&window, 10);
    assert_int_equal(window.hwm, 11);
    assert_window_empty(&window);

    // advancing by more than the window clears it
    assert_true(prenonce_window_consume(&window, 20));
    prenonce_window_advance(&window, 11 + PRENONCE_WINDOW_SIZE + 1);
    assert_int_equal(window.hwm, 11 + PRENONCE_WINDOW_SIZE + 1);
    assert_window_empty(&window);
}

static void test_near_uint32_max(void **state) {
    (void) state;

    prenonce_window_t window = {0};
    prenonce_window_advance(&window, UINT32_MAX - 3);
    assert_int_equal(window.hwm, UINT32_MAX - 3);
    assert_true(prenonce_window_check(&window, UINT32_MAX - 1));
    assert_consume_refused(&window, UINT32_MAX);

    assert_true(prenonce_window_consume(&window, UINT32_MAX - 1));
    assert_true(prenonce_window_consume(&window, UINT32_MAX - 3));
    assert_int_equal(window.hwm, UINT32_MAX - 2);
    assert_true(prenonce_window_consume(&window, UINT32_MAX - 2));

    // every j is consumed
    assert_int_equal(window.hwm, PRENONCE_J_END);
    assert_true(prenonce_window_is_canonical(&window));
    assert_window_empty(&window);
    assert_consume_refused(&window, UINT32_MAX);
    assert_consume_refused(&window, UINT32_MAX - 1);

    prenonce_window_t exhausted = {0};
    prenonce_window_advance(&exhausted, UINT32_MAX);
    assert_memory_equal(&exhausted, &window, sizeof(window));
}

static void test_not_canonical(void **state) {
    (void) state;

    // the bit of hwm is set
    prenonce_window_t window = {0};
    bitvector_set(window.consumed, 0, true);
    assert_false(prenonce_window_is_canonical(&window));

    // a bit is set for j = PRENONCE_J_END
    window = (prenonce_window_t) {0};
    window.hwm = PRENONCE_J_END - 1;
    bitvector_set(window.consumed, 1, true);
    assert_false(prenonce_window_is_canonical(&window));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fresh_window),
        cmocka_unit_test(test_shift),
        cmocka_unit_test(test_full_window),
        cmocka_unit_test(test_below_hwm),
        cmocka_unit_test(test_beyond_window),
        cmocka_unit_test(test_consumed),
        cmocka_unit_test(test_advance),
        cmocka_unit_test(test_near_uint32_max),
        cmocka_unit_test(test_not_canonical),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
