/**
 * Unit tests for the pre-nonce derivation in src/musig/musig_prenonce.c.
 *
 * The expected values are printed by test_utils/gen_prenonce_vectors.py, which uses the BIP-327
 * reference implementation in test_utils/bip0327.py.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "musig_prenonce.h"

#define PRENONCE_NONCE_INIT "0101010101010101010101010101010101010101010101010101010101010101"
#define PRENONCE_WALLET_ID  "0303030303030303030303030303030303030303030303030303030303030303"
#define PRENONCE_SK         "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"
#define PRENONCE_PK         "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
#define PRENONCE_AGG_PK     "03C23464029D664C103F918A0609CE760A0D068BDD78B7E55417558751F4EBC718"

static void unhex_exact(const char *hex, uint8_t *out, size_t len) {
    assert_int_equal(strlen(hex), 2 * len);
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        assert_int_equal(sscanf(hex + 2 * i, "%2x", &byte), 1);
        out[i] = (uint8_t) byte;
    }
}

typedef struct {
    uint32_t j;
    uint32_t i;
    uint32_t k;
    const char *expected_secnonce;
    const char *expected_pubnonce;
} prenonce_case_t;

// clang-format off
static const prenonce_case_t prenonce_cases[] = {
    {
        0x00000000, 0x00000000, 0,
        "157CFA9CC96797B729A2C5A672DB1236F53769B46ADBDAE60350193D4683BA82F9B1BDA2B1DE31BCD5743365B0152408AA21FBC122F68FD1F366695BAC40885803935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "029C9887A61BF12E459C24E2BBBF9249F03756BB5FAB2BF3FC758B1165A8B48F8203308D410AD59E54C3239374122FD50A1C2C7F155188BB3031AE0C121F4044FC62",
    },
    {
        0x00000001, 0x00000000, 0,
        "538AD6564FF1B0BCD6DFF0AC16CC8A6C30B065DA1E2FF945F1A3711C77C83E1252C10D774993647A4B3E0B34FE5A6842C0B298F9DEB5623F41B5133E5B37009C03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "034FD237A01A8F2F8227A582E02D14A67601C40F0D3708FBD8C90FD571CAED229A03C86EC9B0447FD94C04A1581355941E79FD3ECF7A41AD7684EC32F1B7774816C3",
    },
    {
        0x00000000, 0x00000001, 0,
        "723B4FBF8462F7FE03588AC170F08F203F89BA01B41803B2A8567F90497E487830DD1F6E752F1DA4CFBAFE8E277E05A2C30E636D3ED604AF22935B175258916D03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "0299A9E75D0A254EEBC596D906D5457A1A72F4665C756D5C168D6481F8AD036C7203B4649A977FE0E71154EE8B074C88A9E46220CF05FEBFC896F3FFF8AC091EEAB7",
    },
    {
        0x00000000, 0x00000000, 1,
        "0A54A0A49EC13414B27A718C704E2A906C26D6DF2C4FA28825736A13C52378ACDC609F3F0EC04F354350278165183BBCA8554B736692F412BE619EB3070F0BA403935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02DB8D002BD94F6D8D2B46B90D850659088F400176E60B3BE6B7D20A5BFFDB3EEA02C62DEA637961DA9F8D4DE0646E8CF8A63E033AEE09AEB9BC23660684203A1735",
    },
    {
        0x12345678, 0x00000003, 2,
        "1862BE73F1F2C314D6F63ACC7B83598694AD7BAF3B4FB4794103C686F42538C0335A1BB7D14568BD569C537A8164F7D7A3114DADE0BA1B4B9DD09FD3700849E203935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "029D3C47E88AF2F627D3C9477CB328AFB9796AFA9712FC8C4CAEA774CF88E72194021A2AD1464C616BD730F2604BC01C65657026CC561C8D1161095FBD655E84F6F7",
    },
    {
        0xFFFFFFFE, 0xFFFFFFFF, 7,
        "34DA05807E93B6E0BF9307BC3154F90356B2DE03E89181393D79BCD501C5187AD877443534A4C9871FC1DD664D8B9C2BA7E852B3DB9F6694D82EBD8DB43ABFE403935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "038BDFD039AB19DED8EE021DB26B955B9874C7A4C36E7BC78F3CF8D44B525185D60375F1198A8D473A7A3187AEDDF7B93ED308B40FF721D21443D13B0A6F8E4D4BAC",
    },
};
// clang-format on

static void test_prenonce_derive(void **state) {
    (void) state;

    uint8_t nonce_init[32];
    uint8_t wallet_id[32];
    uint8_t sk[32];
    plain_pk_t pk;
    plain_pk_t agg_pk;
    unhex_exact(PRENONCE_NONCE_INIT, nonce_init, sizeof(nonce_init));
    unhex_exact(PRENONCE_WALLET_ID, wallet_id, sizeof(wallet_id));
    unhex_exact(PRENONCE_SK, sk, sizeof(sk));
    unhex_exact(PRENONCE_PK, pk, sizeof(pk));
    unhex_exact(PRENONCE_AGG_PK, agg_pk, sizeof(agg_pk));

    for (size_t t = 0; t < sizeof(prenonce_cases) / sizeof(prenonce_cases[0]); t++) {
        const prenonce_case_t *tc = &prenonce_cases[t];

        musig_secnonce_t secnonce;
        musig_pubnonce_t pubnonce;
        assert_true(musig_prenonce_derive(nonce_init,
                                          tc->j,
                                          tc->i,
                                          tc->k,
                                          wallet_id,
                                          sk,
                                          pk,
                                          agg_pk,
                                          &secnonce,
                                          &pubnonce));

        musig_secnonce_t expected_secnonce;
        musig_pubnonce_t expected_pubnonce;
        unhex_exact(tc->expected_secnonce,
                    (uint8_t *) &expected_secnonce,
                    sizeof(expected_secnonce));
        unhex_exact(tc->expected_pubnonce, expected_pubnonce.raw, sizeof(expected_pubnonce.raw));
        assert_memory_equal(&secnonce, &expected_secnonce, sizeof(secnonce));
        assert_memory_equal(pubnonce.raw, expected_pubnonce.raw, sizeof(pubnonce.raw));
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_prenonce_derive),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
