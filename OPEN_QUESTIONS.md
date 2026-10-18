# Pre-issued MuSig2 nonces: open questions

Points to settle before the `MUSIG2_PRENONCES` build flag is enabled in a release. The design is in
[DESIGN.md](DESIGN.md).

## Blocker: NVRAM write guarantees

- The A/B argument depends on two properties of `nvm_write` that are not documented in the repo or
  the SDK:
  - a torn write only affects the pages of its target, never the other slot;
  - the data is durable when `nvm_write` returns, so that the read-back reflects what survives a
    power cut.
  To confirm with Ledger.
- Also to confirm: flash corruption outside a write cannot leave an older valid record behind
  (for example the newer slot failing validation while the older one still passes, which would
  roll back the consumption of the last `j`). When both slots fail validation, the next GET
  creates a new `nonce_init`, which is safe.

## Deviations from the original spec (to confirm)

- One `j` per signing call instead of one per nonce; each (input, key expression) pair has its own
  nonce derived from `(j, i, k)`.
- Nonces bound to the wallet id, the untweaked aggregate key, the key-expression index and the
  input position, instead of the address and the leaf hash.
- `ADVANCE_MUSIG2_PRENONCES` added.
- The window counts transactions, not nonces.

## Derivation and encoding

- `msg` is absent (not empty) in NonceGen.
- `ser32` is big-endian, while PSBT integers are little-endian. Shared with Coldcard and Kern.

## Commands

- GET writes NVRAM once, to create `nonce_init` lazily.
- No on-device prompt for GET and ADVANCE.
- ADVANCE can exhaust the u32 space: `j = UINT32_MAX` is never usable, and `hwm` at `UINT32_MAX`
  needs a regeneration.
- Whether GET should return `hwm`.
- GET bounds the input positions only by u32 overflow, not by `MAX_N_INPUTS_CAN_SIGN` (512).
- GET and ADVANCE ignore trailing APDU bytes.

## Regeneration and storage

- Regeneration is only possible from the settings menu, with a confirmation. `hwm` resets to 0 with
  a new epoch; the alternative is to keep `hwm` monotonic across epochs.
- A corrupt storage (two valid records with the same `seq`) refuses everything except
  regeneration.
- An app or OS update wipes the state and silently invalidates the outstanding pubnonces.

## Signing

- Swap and BIP-322 are refused in one-round mode.
- Any failure after the commit burns `j`.
- A PSBT mixing one-round and two-round signing for our key is refused.
- One `j` per signing call for all our `musig()` key expressions (`INCONSISTENT_J` otherwise).
  Should we allow one `j` per key?
- Lookup failures map to the error code of the field: a transport error is reported as
  `MALFORMED_J` or `MISSING_PUBNONCE`.
- A host hiding the `j` field makes the device use the two-round flow. Safe, but the device cannot
  detect it.

## UI

- Touch devices: the settings return to their first page after a reset, because
  `nbgl_useCaseHomeAndSettings` does not display the settings when started on a later page.

## Performance

- A 2-input one-round call takes about 4.6 s on Speculos, against about 3.8 s for round 2 of the
  two-round flow (about 5.4 s for both rounds).
- The private key is derived once per validated pair and twice per signed pair.
- Nano X peak stack not measured; the stack canary runs pass.

## Release

- Proprietary identifier `"MUSIG2_PRENONCE"` and batch magic `"MPNB"`, shared with Coldcard and
  Kern.
- Whether the flag may be enabled in mainnet builds before an audit.
- The JS client does not support the new commands nor the PSBT field.
