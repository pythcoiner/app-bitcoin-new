#!/usr/bin/env python3
"""Single-round MuSig2 signing with pre-issued nonces.

A 2-of-2 tr(musig(@0,@1)/**) wallet between the device and a software cosigner:
- the device hands out a batch of pubnonces before the transaction exists;
- the coordinator places them in the PSBT, with the pubnonces of the software cosigner;
- one SIGN_PSBT call returns the partial signatures of the device;
- the coordinator aggregates them with those of the software cosigner and verifies the signature.

The app must be built with MUSIG2_PRENONCES=1. The wallet registration and the transaction must be
approved on the device. Run from the repo root, with speculos running (default 127.0.0.1:9999):

    python dev-tools/musig2_prenonces.py

The software cosigner (test_utils/musig2.py) is NOT a secure implementation: testnet only.
"""

import argparse
import os
import secrets
import sys
from typing import List, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from embit.bip32 import HDKey  # noqa: E402
from embit.networks import NETWORKS  # noqa: E402

from bitcoin_client.ledger_bitcoin import Chain, Musig2PrenonceBatch, MusigPartialSignature, TransportClient, WalletPolicy, createClient  # noqa: E402
from bitcoin_client.ledger_bitcoin.client_base import Client  # noqa: E402
from bitcoin_client.ledger_bitcoin.exception.errors import BadStateError  # noqa: E402
from bitcoin_client.ledger_bitcoin.key import ExtendedKey  # noqa: E402
from bitcoin_client.ledger_bitcoin.psbt import PSBT  # noqa: E402
from test_utils import bip0327, bip0340, txmaker  # noqa: E402
from test_utils.musig2 import HotMusig2Cosigner, TrDescriptorTemplate, aggregate_musig_pubkey, process_placeholder  # noqa: E402
from test_utils.taproot_sighash import SIGHASH_DEFAULT, TaprootSignatureHash  # noqa: E402

ACCOUNT_PATH = "m/48'/1'/0'/2'"

# index of musig(@0,@1) in the descriptor template
KEYEXPR_INDEX = 0

INPUT_AMOUNTS = [100_000, 200_000]
OUTPUT_AMOUNTS = [290_000]


def software_cosigner_key() -> Tuple[str, str]:
    # a fresh testnet account key for the software cosigner
    root = HDKey.from_seed(secrets.token_bytes(32), version=NETWORKS["test"]["xprv"])
    return root.derive(ACCOUNT_PATH).to_base58(), root.my_fingerprint.hex()


def register_wallet(client: Client, cosigner_xpub: str, cosigner_fingerprint: str):
    device_fingerprint = client.get_master_fingerprint().hex()
    device_xpub = client.get_extended_pubkey(ACCOUNT_PATH)
    origin = ACCOUNT_PATH[1:]
    wallet = WalletPolicy(
        name="Musig pre-nonces",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[
            f"[{device_fingerprint}{origin}]{device_xpub}",
            f"[{cosigner_fingerprint}{origin}]{cosigner_xpub}",
        ],
    )
    print("Approve the wallet registration on the device")
    _, wallet_hmac = client.register_wallet(wallet)
    return wallet, wallet_hmac


def current_hwm(client: Client) -> int:
    # ADVANCE below the high-water mark changes nothing and returns it; it is refused when no
    # batch was ever issued
    try:
        return client.advance_musig2_prenonces(0)
    except BadStateError:
        return 0


def place_batch(wallet: WalletPolicy, psbt: PSBT, batch: Musig2PrenonceBatch) -> None:
    # each pubnonce goes under the BIP-373 key of its input: (participant key, tweaked aggregate
    # key, leaf hash), here a keypath spend
    desc_tmpl = TrDescriptorTemplate.from_string(wallet.descriptor_template)
    placeholder, tapleaf_desc = list(desc_tmpl.placeholders())[batch.k]
    agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(wallet.keys_info[i] for i in placeholder.key_indexes)
    for i, pubnonce in batch.pubnonces:
        _, _, _, aggpk_tweaked = process_placeholder(
            wallet, psbt.inputs[i], placeholder, keyagg_ctx, ExtendedKey.deserialize(agg_xpub_str), tapleaf_desc,
            desc_tmpl)
        psbt.inputs[i].musig2_pub_nonces[(batch.pk, aggpk_tweaked, None)] = pubnonce
    psbt.set_musig2_prenonce_j(batch.pk, batch.j)


def aggregate_and_verify(wallet: WalletPolicy, psbt: PSBT) -> List[bytes]:
    desc_tmpl = TrDescriptorTemplate.from_string(wallet.descriptor_template)
    placeholder, tapleaf_desc = list(desc_tmpl.placeholders())[KEYEXPR_INDEX]
    agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(wallet.keys_info[i] for i in placeholder.key_indexes)
    pubkeys = sorted(
        ExtendedKey.deserialize(wallet.keys_info[i][wallet.keys_info[i].find(']') + 1:]).pubkey
        for i in placeholder.key_indexes)
    spent_utxos = [input.witness_utxo for input in psbt.inputs]

    signatures = []
    for input_index, input in enumerate(psbt.inputs):
        tweaks, is_xonly, _, aggpk_tweaked = process_placeholder(
            wallet, input, placeholder, keyagg_ctx, ExtendedKey.deserialize(agg_xpub_str), tapleaf_desc, desc_tmpl)
        sighash = TaprootSignatureHash(psbt.tx, spent_utxos, SIGHASH_DEFAULT, input_index)
        session_ctx = bip0327.SessionContext(
            aggnonce=bip0327.nonce_agg([input.musig2_pub_nonces[(pk, aggpk_tweaked, None)] for pk in pubkeys]),
            pubkeys=pubkeys,
            tweaks=tweaks,
            is_xonly=is_xonly,
            msg=sighash)
        signature = bip0327.partial_sig_agg(
            [input.musig2_partial_sigs[(pk, aggpk_tweaked, None)] for pk in pubkeys], session_ctx)
        if not bip0340.schnorr_verify(sighash, aggpk_tweaked[1:], signature):
            raise RuntimeError(f"Invalid signature for input {input_index}")
        signatures.append(signature)
    return signatures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1", help="speculos host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="speculos APDU port (default: 9999)")
    parser.add_argument("--hid", action="store_true", help="use a device over USB instead of speculos")
    args = parser.parse_args()

    if args.hid:
        transport = TransportClient(interface="hid")
    else:
        transport = TransportClient(interface="tcp", server=args.host, port=args.port)
    client = createClient(transport, chain=Chain.TEST)

    cosigner_xpriv, cosigner_fingerprint = software_cosigner_key()
    cosigner_xpub = ExtendedKey.deserialize(cosigner_xpriv).neutered().to_string()
    wallet, wallet_hmac = register_wallet(client, cosigner_xpub, cosigner_fingerprint)
    cosigner = HotMusig2Cosigner(wallet, cosigner_xpriv)

    # before the transaction exists: the coordinator picks an unused j and fetches the batch for
    # as many input positions as it may fill; the batch can be stored as a file or a QR code
    j = current_hwm(client)
    batch = client.get_musig2_prenonces(wallet, wallet_hmac, j, KEYEXPR_INDEX, 0, len(INPUT_AMOUNTS))
    mpnb = batch.serialize()
    print(f"Batch j={j}: {len(batch.pubnonces)} pubnonces, MPNB {len(mpnb)} bytes")

    # later: the transaction, with the pubnonces of both participants and our j
    psbt = txmaker.createPsbt(wallet, INPUT_AMOUNTS, OUTPUT_AMOUNTS, [False])
    place_batch(wallet, psbt, Musig2PrenonceBatch.deserialize(mpnb))
    cosigner.generate_public_nonces(psbt)

    # one signing call on the device
    print("Approve the transaction on the device")
    for input_index, yielded in client.sign_psbt(psbt, wallet, wallet_hmac):
        if isinstance(yielded, MusigPartialSignature):
            psbt_key = (yielded.participant_pubkey, yielded.aggregate_pubkey, yielded.tapleaf_hash)
            psbt.inputs[input_index].musig2_partial_sigs[psbt_key] = yielded.partial_signature

    cosigner.generate_partial_signatures(psbt)

    for input_index, signature in enumerate(aggregate_and_verify(wallet, psbt)):
        print(f"Input {input_index}: valid signature {signature.hex()}")


if __name__ == "__main__":
    main()
