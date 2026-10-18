#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Local headers */
#include "musig.h"

/**
 * Derives the (secnonce, pubnonce) pair of the pre-nonce batch j, for the input at position i and
 * the key expression with index k:
 *
 *   rand' = tagged_hash("MuSig2Prenonce", nonce_init || ser32(j) || ser32(i) || ser32(k) ||
 *                       wallet_id || pk || agg_pk)
 *   NonceGen(rand', sk, pk, aggpk = x-only agg_pk, msg absent, extra_in = ser32(j))
 *
 * with ser32 big-endian. The nonce does not depend on the transaction, so that it can be issued
 * before the transaction exists.
 *
 * @param[in]  nonce_init
 *   The 32-byte secret of the pre-nonce state.
 * @param[in]  j
 *   The index of the batch.
 * @param[in]  i
 *   The position of the input in the PSBT.
 * @param[in]  k
 *   The index of the musig() key expression in the descriptor template.
 * @param[in]  wallet_id
 *   The 32-byte id of the wallet policy.
 * @param[in]  sk
 *   The 32-byte secret key of the signer.
 * @param[in]  pk
 *   The 33-byte public key of the signer.
 * @param[in]  agg_pk
 *   The 33-byte aggregate public key of the musig() key expression, before any tweak.
 * @param[out] secnonce
 *   Pointer to receive the secret nonce; zeroed out on failure.
 * @param[out] pubnonce
 *   Pointer to receive the public nonce.
 *
 * @return true on success, false otherwise.
 */
bool musig_prenonce_derive(const uint8_t nonce_init[static 32],
                           uint32_t j,
                           uint32_t i,
                           uint32_t k,
                           const uint8_t wallet_id[static 32],
                           const uint8_t sk[static 32],
                           const plain_pk_t pk,
                           const plain_pk_t agg_pk,
                           musig_secnonce_t *secnonce,
                           musig_pubnonce_t *pubnonce);
