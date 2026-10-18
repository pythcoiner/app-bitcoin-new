# Pre-issued MuSig2 nonces

One-round MuSig2 signing: the device hands out pubnonces before a transaction exists, and a later
`SIGN_PSBT` on a PSBT that already carries the pubnonces of every participant returns the partial
signatures in a single call. The two-round flow of [doc/musig.md](doc/musig.md) is unchanged.

The feature is built only with `MUSIG2_PRENONCES=1` (`HAVE_MUSIG2_PRENONCES`, see `Makefile`). With
the flag off, the app is the same as without this work.

The protocol is shared with Coldcard and Kern: the key-expression index `k`, the batch encoding and
the PSBT field below must be identical on all of them. Open points are in
[OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).

## Flow

1. The coordinator picks a batch index `j` and calls `GET_MUSIG2_PRENONCES` for a registered
   `tr()` wallet policy, a `musig()` key expression `k` and a range of input positions. The device
   returns one pubnonce per input position, its participant key `pk`, the untweaked aggregate key
   `agg_pk` and its high-water mark `hwm`. No prompt, no state change except the lazy creation of
   `nonce_init`.
2. Later, the coordinator builds the PSBT, puts each pubnonce under the BIP-373 key of its input
   (`pk`, tweaked aggregate key, leaf hash), adds the pubnonces of the cosigners and sets the global
   `j` field for `pk`.
3. `SIGN_PSBT` checks everything, shows the usual review, consumes `j` in NVRAM after the approval,
   then yields the partial signatures.

Each `j` is used by at most one `SIGN_PSBT`, ever. This is the only rule the safety depends on.

## Code locations

| Path | Role |
|------|------|
| `Makefile` | `MUSIG2_PRENONCES ?= 0` build flag |
| `src/musig/musig.{h,c}` | `musig_nonce_gen_ext`: BIP-327 NonceGen with `sk`, `msg` and `extra_in`; `musig_nonce_gen` wraps it with identical output |
| `src/musig/musig_prenonce.{h,c}` | `musig_prenonce_derive`: nonce derivation from `nonce_init` |
| `src/musig/prenonce_window.{h,c}` | consumption window: `check`, `consume`, `advance`, canonical form |
| `src/musig/prenonce_storage.{h,c}` | A/B NVRAM records: load, create, store, regenerate |
| `src/handler/get_musig2_prenonces.c` | `GET_MUSIG2_PRENONCES` |
| `src/handler/advance_musig2_prenonces.c` | `ADVANCE_MUSIG2_PRENONCES` |
| `src/commands.h`, `src/handler/handlers.h`, `src/main.c` | INS 0x06 and 0x07, command table (not in the swap allowlist) |
| `src/error_codes.h` | error codes of the two commands and of the one-round `SIGN_PSBT` path |
| `src/handler/sign_psbt/psbt_fields.{h,c}` | detection and reading of the global `j` field |
| `src/handler/sign_psbt/init_global_state.{h,c}` | `has_musig2_prenonce_j`; `fill_keyexpr_info_if_internal` takes the wallet header, so that GET can reuse it |
| `src/handler/sign_psbt.{h,c}` | `prenonce_signing_state_t`; validation before the review, commit after the approval |
| `src/handler/sign_psbt/sign_input.{h,c}` | `validate_musig2_prenonces`, `commit_musig2_prenonce`, loop over (input, `musig()`) pairs shared with round 1, dispatch to the one-round signer |
| `src/handler/sign_psbt/musig_signing.{h,c}` | `validate_musig_prenonce`, `sign_sighash_musig_prenonce_and_yield`; nonce aggregation and signing helpers shared with round 2 |
| `src/ui/menu_nbgl.c` | "Reset MuSig2 pre-nonces" settings entry with confirmation |
| `unit-tests/test_musig.c` | BIP-327 NonceGen vectors |
| `unit-tests/test_prenonce_window.c` | window edge cases |
| `unit-tests/test_prenonce_storage.c` | A/B records, write torn at every byte |
| `unit-tests/test_musig_prenonce.c`, `test_utils/gen_prenonce_vectors.py` | derivation vectors, cross-checked with `test_utils/bip0327.py` |
| `tests/test_musig2_prenonces.py` | GET, ADVANCE, window, reset menu |
| `tests/test_sign_psbt_musig_prenonces.py` | one-round signing, refusals, rejection and interruption |
| `bitcoin_client/ledger_bitcoin/` | Python client: `get_musig2_prenonces`, `advance_musig2_prenonces`, `Musig2PrenonceBatch`, `PSBT.set_musig2_prenonce_j` / `get_musig2_prenonce_j` |
| `bitcoin_client_rs/src/` | Rust client: same commands, `Musig2PrenonceBatch`, `psbt::set_musig2_prenonce_j` / `get_musig2_prenonce_j` |
| `dev-tools/musig2_prenonces.py` | end-to-end example with a software cosigner |
| `.github/workflows/build_and_functional_tests.yml` | build and Ragger tests with the flag on |

## Nonce derivation

For batch `j`, input position `i` and key-expression index `k`:

```
rand' = tagged_hash("MuSig2Prenonce", nonce_init || ser32(j) || ser32(i) || ser32(k) || wallet_id || pk || agg_pk)
(secnonce, pubnonce) = NonceGen(rand', sk, pk, aggpk = xonly(agg_pk), msg absent, extra_in = ser32(j))
```

- `ser32` is big-endian.
- `wallet_id`: `get_policy_wallet_id` of the registered policy.
- `pk`: our participant key, `keyexpr_info->internal_pubkey`.
- `agg_pk`: the untweaked aggregate key, `keyexpr_info->pubkey`, as round 1 of the two-round flow.
- `k`: 0-based position of the key expression in the descriptor template, without deduplication
  (`keyexpr_info->index`).

All the inputs are computed on the device from the registered policy, never taken from the host.
Distinct `(j, i, k)` give distinct `rand'`, and `nonce_init` never leaves the device.

## Persistent state

### Record

`prenonce_state_t` is `{epoch u32, window {hwm u32, consumed[16]}, nonce_init[32]}`. It is stored in
`prenonce_record_t`:

| Field | Size | |
|-------|------|-|
| `magic` | 4 | `0x4d32504e` |
| `version` | 2 | 1 |
| `window_bits` | 2 | 128 |
| `seq` | 4 | incremented on each write |
| `state` | 56 | epoch, window, `nonce_init` |
| `checksum` | 32 | tagged hash `MuSig2PrenonceRecord` of the fields above |

100 bytes in total. A record is valid if the magic, version, window size and checksum match and
the window is canonical (bit of `hwm` clear, no bit set at or above `UINT32_MAX`).

The window holds `j` from `hwm` to `hwm + 127`. Every `j` below `hwm` is consumed. Consuming `j`
sets its bit, then moves `hwm` past the run of consumed bits. `ADVANCE` sets `hwm` to the maximum of
`hwm` and the requested value. `j = UINT32_MAX` is never usable.

### NVRAM layout and size

Two copies, `N_prenonce_slots_real[2]`, each in a 512-byte aligned slot, so that each slot has its
own NVRAM pages on every target (page size: 256 bytes on Nano X, 512 on the others). The slots are
`const` data, initialized to zeros, that is with no valid record.

`dataSize` of the app:

| Target | Flag off | Flag on |
|--------|----------|---------|
| Nano S+ (`nanos2`) | 1024 | 2048 |
| Nano X (`nanox`) | 768 | 2048 |
| Stax | 1024 | 2048 |
| Flex | 1024 | 2048 |
| Apex P | 1024 | 2048 |

### Atomic write

`prenonce_storage_store` loads both slots, takes the valid record with the highest `seq`, writes
the new state with `seq + 1` to the other slot with `nvm_write`, then reads it back. It succeeds only
if the read-back matches. The previous record is never touched by the write.

`SIGN_PSBT` computes partial signatures only after this succeeds for the commit of `j`. So any state
a power cut can leave either has `j` consumed, or comes from a moment when no signature for `j`
existed.

This argument depends on two properties of `nvm_write` that are not documented in the repo or the
SDK: a torn write only affects the pages of its target, and the data is durable when it returns.
See [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).

### Power-loss states

Current record in slot A with `seq = n`, new state written to slot B.

| Power cut | State after restart | Effect |
|-----------|---------------------|--------|
| before `nvm_write` | A (old) | nothing changed |
| during `nvm_write` | A (old), B fails its checksum | commit of `j`: `j` still usable, no signature was produced |
| after `nvm_write`, before the read-back ends | B (new) | `j` consumed, no signature: `j` burned |
| after the commit, while signing | B (new) | `j` consumed, some partial signatures may have been sent: `j` burned |
| during the first write (creation by GET) | empty | the next GET creates a new `nonce_init`; no pubnonce of the torn one was ever sent |
| during regeneration | A (old) or B (new) | the user sees no success status and can retry |
| during `ADVANCE` | A (old) or B (new) | `hwm` raised or not; the host can retry |

If both slots fail validation, the storage is empty and the next GET creates a fresh `nonce_init`.
If the two slots hold different valid records with the same `seq`, the storage is corrupt: GET,
ADVANCE and SIGN_PSBT refuse it, and only regeneration writes past it.

### Creation, regeneration, updates

- `nonce_init` comes from `cx_get_random_bytes`. It is created by the first GET (one NVRAM write).
  SIGN_PSBT and ADVANCE never create it.
- Regeneration: settings menu, "Reset MuSig2 pre-nonces", with a confirmation. New `nonce_init`,
  `epoch + 1`, empty window (`hwm = 0`). Every issued pubnonce becomes unusable. The host cannot
  trigger it.
- App or OS update wipes all the `N_` data. `nonce_init` and the window are in the same record, so
  they are lost together: no rollback, but outstanding pubnonces become unusable.

## Encodings

### PSBT field

Global BIP-174 proprietary entry, one per participating signer:

- key: `0xFC || 0x0F || "MUSIG2_PRENONCE" || 0x00 || pk[33]`
- value: `ser32(j)`, 4 bytes big-endian

The device builds the key from its own `pk` and reads the value; it does not parse keys of other
signers. Any key starting with the prefix marks the PSBT as having pre-nonce fields
(`has_musig2_prenonce_j`). A PSBT with the field for our `pk` is a one-round request for us.

### Batch (MPNB)

Binary form for files and QR codes, implemented by `Musig2PrenonceBatch.serialize` in the Python and
Rust clients:

```
"MPNB" || 0x01 || ser32(j) || ser32(k) || pk[33] || agg_pk[33] || ser32(hwm) || compactsize(n) || n x (ser32(i) || pubnonce[66])
```

The APDU encodings of `GET_MUSIG2_PRENONCES` and `ADVANCE_MUSIG2_PRENONCES` are in
[doc/bitcoin.md](doc/bitcoin.md).

## One-round SIGN_PSBT

- After the transaction hashes are computed (`sign_psbt.c`), `validate_musig2_prenonces` reads the
  `j` field of the participant key of every `musig()` key expression we sign. They must all have
  the same `j`, or none has it (two-round flow).
- Refused: swap, BIP-322, no pubnonce in the PSBT, no state, `j` not available in the window.
- For each (internal input, `musig()` key expression) pair: recompute our pubnonce from `(j, i, k)`
  and compare it to ours in the PSBT, then check the cosigner pubnonces and aggregate them. Every
  pair must be covered, so a PSBT mixing one-round and two-round for our key is refused.
- Any failure aborts before the review, with a specific error code; nothing is consumed.
- `display_transaction` as for any PSBT. Rejection consumes nothing.
- After the approval, `commit_musig2_prenonce` reloads the state, checks that `epoch` and
  `nonce_init` are those of the validation, consumes `j` and stores the record.
- `sign_sighash_musig_prenonce_and_yield` refuses to sign if the commit did not happen in this
  call, derives the nonce again, signs and yields with the partial-signature tag of round 2. It
  never touches the two-round sessions, so a pending two-round session survives.

## Deviations from the original spec

- One `j` per signing call, not per nonce. Inside it, each (input, key expression) pair has its own
  nonce derived from `(j, i, k)`. Only `j` is tracked, and the window counts transactions.
- Nonces are bound to the wallet id, the untweaked aggregate key, the key-expression index and the
  input position, not to the address and the leaf hash. A batch serves any inputs of the wallet;
  the leaf is fixed by `k`.
- `ADVANCE_MUSIG2_PRENONCES` was added, so an issued and abandoned `j` cannot pin the window.

## Threat model

Host, coordinator and cosigners are untrusted.

| Attack | How it is stopped |
|--------|-------------------|
| Same `j` on two PSBTs | the first signing consumes `j`; the second is refused with `J_NOT_AVAILABLE` before the review |
| `j < hwm` | `prenonce_window_check` refuses it, in GET and SIGN_PSBT |
| `j` beyond the window | refused the same way; at most 128 transactions can be outstanding |
| Batch of another wallet | `wallet_id` is in `rand'`: the recomputed pubnonce differs, `PUBNONCE_MISMATCH` |
| Batch of another `musig()` or leaf | `agg_pk` and `k` are in `rand'`: `PUBNONCE_MISMATCH` |
| Pubnonce moved to another input | `i` is in `rand'`: `PUBNONCE_MISMATCH` |
| Tampered own pubnonce | `PUBNONCE_MISMATCH` |
| Missing or invalid cosigner pubnonce | `COSIGNER_PUBNONCE` before the review |
| Wrong but valid cosigner pubnonce | the aggregate signature is invalid; our secnonce is used once, so nothing leaks |
| Replay of a signed PSBT | `j` is consumed: refused |
| Power cut before the commit | `j` was not consumed and no signature exists: `j` usable again |
| Power cut after the commit | `j` stays consumed: burned |
| User rejection | nothing consumed, `j` usable again |
| Regeneration | new `nonce_init`: old pubnonces give `PUBNONCE_MISMATCH`; a regeneration between validation and commit makes the commit fail |
| Host hides the `j` field | the device runs the two-round flow, whose round 2 only accepts pubnonces of its own session: no signature with a pre-nonce |
| App or OS update wipes the state | `nonce_init` goes with the window: old pubnonces give `PUBNONCE_MISMATCH` |

A rollback of the record to an older valid copy would allow reuse of `j`. The A/B write prevents it
under the `nvm_write` assumptions above.

## Tests

- C unit tests (`unit-tests/`): NonceGen vectors, window edge cases, records with a write torn at
  every byte, derivation vectors.
- Ragger tests with the flag on (`tests/test_musig2_prenonces.py`,
  `tests/test_sign_psbt_musig_prenonces.py`): happy paths (keypath, tapleaf, several inputs, two
  `musig()` in one leaf) with the aggregate signature verified, every refusal of the threat model,
  rejection, interruption before and after the commit, regeneration, coexistence with a pending
  two-round session. They are skipped when the app is built without the flag.
- The existing MuSig2 tests pass with the flag on and off.
