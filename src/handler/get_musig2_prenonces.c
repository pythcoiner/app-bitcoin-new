/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2026 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_MUSIG2_PRENONCES

#include <stdint.h>
#include <string.h>

/* SDK headers */
#include "buffer.h"
#include "crypto_helpers.h"
#include "write.h"

/* Local headers */
#include "client_commands.h"
#include "commands.h"
#include "constants.h"
#include "crypto.h"
#include "error_codes.h"
#include "get_preimage.h"
#include "handlers.h"
#include "init_global_state.h"
#include "musig_prenonce.h"
#include "policy.h"
#include "prenonce_storage.h"
#include "sw.h"
#include "wallet.h"

// maximum number of input positions in one request
#define MAX_PRENONCE_INPUT_COUNT 32

typedef union {
    uint8_t bytes[MAX_WALLET_POLICY_BYTES];
    policy_node_t parsed;
} wallet_policy_map_t;

// Fetches and parses the registered wallet policy with the given id and hmac.
static bool __attribute__((noinline)) load_registered_wallet(
    dispatcher_context_t *dc,
    const uint8_t wallet_id[static 32],
    const uint8_t wallet_hmac[static 32],
    policy_map_wallet_header_t *wallet_header,
    wallet_policy_map_t *wallet_policy_map) {
    if (is_array_all_zeros(wallet_hmac, 32)) {
        PRINTF("The wallet policy must be registered\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_MISSING_HMAC);
        return false;
    }

    if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
        PRINTF("Incorrect hmac\n");
        SEND_SW(dc, SW_SIGNATURE_FAIL);
        return false;
    }

    uint8_t serialized_wallet_policy[MAX_WALLET_POLICY_SERIALIZED_LENGTH];
    int serialized_wallet_policy_len = call_get_preimage(dc,
                                                         wallet_id,
                                                         serialized_wallet_policy,
                                                         sizeof(serialized_wallet_policy));
    if (serialized_wallet_policy_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    buffer_t serialized_wallet_policy_buf =
        buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);

    uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];
    if (0 > read_and_parse_wallet_policy(dc,
                                         &serialized_wallet_policy_buf,
                                         wallet_header,
                                         policy_map_descriptor,
                                         wallet_policy_map->bytes,
                                         sizeof(wallet_policy_map->bytes))) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    uint8_t computed_wallet_id[32];
    get_policy_wallet_id(wallet_header, computed_wallet_id);
    if (memcmp(wallet_id, computed_wallet_id, sizeof(computed_wallet_id)) != 0) {
        PRINTF("Mismatching wallet policy id\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (wallet_policy_map->parsed.type != TOKEN_TR) {
        PRINTF("The wallet policy is not a tr() policy\n");
        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_GET_MUSIG2_PRENONCES_NOT_TAPROOT);
        return false;
    }

    return true;
}

// Fills keyexpr_info for the key expression with index k, that must be a musig() with an internal
// key.
static bool __attribute__((noinline)) get_internal_musig_keyexpr(
    dispatcher_context_t *dc,
    const policy_map_wallet_header_t *wallet_header,
    const policy_node_t *policy,
    uint64_t k,
    keyexpr_info_t *keyexpr_info) {
    memset(keyexpr_info, 0, sizeof(*keyexpr_info));

    int n_key_expressions =
        get_keyexpr_by_index(policy, (unsigned int) k, NULL, &keyexpr_info->key_expression_ptr);
    if (n_key_expressions < 0) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    if (k >= (uint64_t) n_key_expressions ||
        keyexpr_info->key_expression_ptr->type != KEY_EXPRESSION_MUSIG) {
        PRINTF("Key expression %d is not a musig()\n", (int) k);
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_NOT_INTERNAL_MUSIG);
        return false;
    }
    keyexpr_info->index = (int) k;

    if (!fill_keyexpr_info_if_internal(dc,
                                       wallet_header,
                                       crypto_get_master_key_fingerprint(),
                                       keyexpr_info)) {
        PRINTF("The musig() has no internal key\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_NOT_INTERNAL_MUSIG);
        return false;
    }
    return true;
}

static bool yield_prenonce(dispatcher_context_t *dc, uint32_t i, const musig_pubnonce_t *pubnonce) {
    // bytes:     1          4          66
    //        CMD_YIELD <ser32(i)> <pubnonce>
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t i_be[4];
    write_u32_be(i_be, 0, i);
    dc->add_to_response(i_be, sizeof(i_be));

    dc->add_to_response(pubnonce->raw, sizeof(pubnonce->raw));

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    return dc->process_interruption(dc) >= 0;
}

// Derives and yields the pubnonces of the batch j for the input positions starting at
// input_start. On failure, it already sends an error status word.
static bool __attribute__((noinline)) derive_and_yield_prenonces(dispatcher_context_t *dc,
                                                                 const prenonce_state_t *state,
                                                                 uint32_t j,
                                                                 const uint8_t wallet_id[static 32],
                                                                 const keyexpr_info_t *keyexpr_info,
                                                                 uint32_t input_start,
                                                                 uint8_t input_count) {
    cx_ecfp_private_key_t private_key = {0};
    if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                      keyexpr_info->key_derivation,
                                      keyexpr_info->key_derivation_length,
                                      &private_key,
                                      NULL) != CX_OK) {
        explicit_bzero(&private_key, sizeof(private_key));
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    bool ok = true;
    for (uint8_t n = 0; n < input_count && ok; n++) {
        uint32_t i = input_start + n;

        musig_secnonce_t secnonce;
        musig_pubnonce_t pubnonce;
        ok = musig_prenonce_derive(state->nonce_init,
                                   j,
                                   i,
                                   (uint32_t) keyexpr_info->index,
                                   wallet_id,
                                   private_key.d,
                                   keyexpr_info->internal_pubkey.compressed_pubkey,
                                   keyexpr_info->pubkey.compressed_pubkey,
                                   &secnonce,
                                   &pubnonce);
        explicit_bzero(&secnonce, sizeof(secnonce));

        ok = ok && yield_prenonce(dc, i, &pubnonce);
    }

    explicit_bzero(&private_key, sizeof(private_key));

    if (!ok) {
        PRINTF("Failed to derive or yield a pre-nonce\n");
        SEND_SW(dc, SW_BAD_STATE);
    }
    return ok;
}

void handler_get_musig2_prenonces(dispatcher_context_t *dc, uint8_t protocol_version) {
    UNUSED(protocol_version);

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];
    uint32_t j;
    uint64_t k;
    uint32_t input_start;
    uint8_t input_count;

    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, sizeof(wallet_id)) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, sizeof(wallet_hmac)) ||
        !buffer_read_u32(&dc->read_buffer, &j, BE) || !buffer_read_varint(&dc->read_buffer, &k) ||
        !buffer_read_u32(&dc->read_buffer, &input_start, BE) ||
        !buffer_read_u8(&dc->read_buffer, &input_count)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (input_count == 0 || input_count > MAX_PRENONCE_INPUT_COUNT ||
        (uint32_t) (input_count - 1) > UINT32_MAX - input_start) {
        PRINTF("Invalid range of input positions\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_INVALID_INPUT_RANGE);
        return;
    }

    policy_map_wallet_header_t wallet_header;
    wallet_policy_map_t wallet_policy_map;
    if (!load_registered_wallet(dc, wallet_id, wallet_hmac, &wallet_header, &wallet_policy_map)) {
        return;
    }

    keyexpr_info_t keyexpr_info;
    if (!get_internal_musig_keyexpr(dc,
                                    &wallet_header,
                                    &wallet_policy_map.parsed,
                                    k,
                                    &keyexpr_info)) {
        return;
    }

    prenonce_state_t state;
    if (!prenonce_storage_load_or_init(&state)) {
        PRINTF("Failed to load the pre-nonce state\n");
        SEND_SW_EC(dc, SW_BAD_STATE, EC_GET_MUSIG2_PRENONCES_STATE_UNAVAILABLE);
        return;
    }

    if (!prenonce_window_check(&state.window, j)) {
        explicit_bzero(&state, sizeof(state));
        PRINTF("j is not available\n");
        SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_J_NOT_AVAILABLE);
        return;
    }

    bool ok = derive_and_yield_prenonces(dc,
                                         &state,
                                         j,
                                         wallet_id,
                                         &keyexpr_info,
                                         input_start,
                                         input_count);
    uint32_t hwm = state.window.hwm;
    explicit_bzero(&state, sizeof(state));
    if (!ok) {
        return;
    }

    // bytes:  33     33      4
    //         pk   agg_pk   hwm
    uint8_t response[33 + 33 + 4];
    memcpy(response, keyexpr_info.internal_pubkey.compressed_pubkey, 33);
    memcpy(response + 33, keyexpr_info.pubkey.compressed_pubkey, 33);
    write_u32_be(response, 33 + 33, hwm);

    SEND_RESPONSE(dc, response, sizeof(response), SW_OK);
}

#endif  // HAVE_MUSIG2_PRENONCES
