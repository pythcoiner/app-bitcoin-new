from hashlib import sha256
import hmac
from typing import List, Tuple

import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ledger_bitcoin import Musig2PrenonceBatch
from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import WalletPolicy
from ragger_bitcoin import RaggerClient
from test_utils import SpeculosGlobals, txmaker
from test_utils.musig2 import HotMusig2Cosigner, MuSig2KeyPlaceholder, TrDescriptorTemplate, aggregate_musig_pubkey, process_placeholder, run_musig2_test
from test_utils.taproot_sighash import SIGHASH_DEFAULT, TaprootSignatureHash

from .instructions import sign_psbt_instruction_approve
from .test_sign_psbt_musig import KEYPATH_COSIGNER_2_XPRIV, KEYPATH_PSBT_B64, KEYPATH_SIGHASHES, SCRIPTPATH_COSIGNER_1_XPUB, SCRIPTPATH_COSIGNER_2_XPRIV, SCRIPTPATH_COSIGNER_2_XPUB, SCRIPTPATH_INTERNAL_XPUB, SCRIPTPATH_PSBT_B64, SCRIPTPATH_SIGHASHES, LedgerMusig2Cosigner, keypath_wallet_policy, musig_pubnonce_ids, scriptpath_wallet_policy

SW_INS_NOT_SUPPORTED = 0x6D00


@pytest.fixture(autouse=True)
def require_prenonces(client: RaggerClient):
    # with a fresh state, ADVANCE is refused with SW_BAD_STATE if the app supports it
    with pytest.raises(ExceptionRAPDU) as e:
        client.advance_musig2_prenonces(0)
    if e.value.status == SW_INS_NOT_SUPPORTED:
        pytest.skip("app built without MUSIG2_PRENONCES")


def register(speculos_globals: SpeculosGlobals, wallet_policy: WalletPolicy) -> Tuple[WalletPolicy, bytes]:
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()
    return wallet_policy, wallet_hmac


def get_prenonce_batches(client: RaggerClient, wallet_policy: WalletPolicy, wallet_hmac: bytes, pubkey: bytes,
                         j: int, n_inputs: int) -> List[Musig2PrenonceBatch]:
    # the batch j of each musig() with our key, for the input positions 0 to n_inputs - 1
    batches = []
    desc_tmpl = TrDescriptorTemplate.from_string(wallet_policy.descriptor_template)
    for k, (placeholder, _) in enumerate(desc_tmpl.placeholders()):
        if not isinstance(placeholder, MuSig2KeyPlaceholder):
            continue
        participant_keys = [wallet_policy.keys_info[i] for i in placeholder.key_indexes]
        if not any(ExtendedKey.deserialize(key_info[key_info.find(']') + 1:]).pubkey == pubkey
                   for key_info in participant_keys):
            continue
        batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, j, k, 0, n_inputs)
        assert batch.pk == pubkey
        batches.append(batch)
    return batches


def place_prenonces(wallet_policy: WalletPolicy, psbt: PSBT, batches: List[Musig2PrenonceBatch]) -> None:
    # As a coordinator would: places each pubnonce under the BIP-373 key of its input, and sets j
    ids = musig_pubnonce_ids(wallet_policy, psbt)
    for batch in batches:
        for i, pubnonce in batch.pubnonces:
            aggpk_tweaked, leaf_hash = ids[(i, batch.k)]
            psbt.inputs[i].musig2_pub_nonces[(batch.pk, aggpk_tweaked, leaf_hash)] = pubnonce
        psbt.set_musig2_prenonce_j(batch.pk, batch.j)


class PrenonceMusig2Cosigner(LedgerMusig2Cosigner):
    """
    A LedgerMusig2Cosigner whose pubnonces come from a pre-issued batch: the device signs in a
    single SIGN_PSBT call.
    """

    def __init__(self, j: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.j = j

    def generate_public_nonces(self, psbt: PSBT) -> None:
        batches = get_prenonce_batches(self.client, self.wallet_policy, self.wallet_hmac, self.pubkey.pubkey, self.j,
                                       len(psbt.inputs))
        place_prenonces(self.wallet_policy, psbt, batches)


def compute_sighashes(wallet_policy: WalletPolicy, psbt: PSBT) -> List[bytes]:
    # the sighash of each input, for the leaf of the musig() key expressions (all in the same leaf)
    desc_tmpl = TrDescriptorTemplate.from_string(wallet_policy.descriptor_template)
    spent_utxos = [input.witness_utxo for input in psbt.inputs]
    sighashes = []
    for input_index, input in enumerate(psbt.inputs):
        input_sighashes = set()
        for placeholder, tapleaf_desc in desc_tmpl.placeholders():
            if not isinstance(placeholder, MuSig2KeyPlaceholder):
                continue
            agg_xpub_str, keyagg_ctx = aggregate_musig_pubkey(
                wallet_policy.keys_info[i] for i in placeholder.key_indexes)
            _, _, leaf_script, _ = process_placeholder(
                wallet_policy, input, placeholder, keyagg_ctx, ExtendedKey.deserialize(agg_xpub_str), tapleaf_desc,
                desc_tmpl)
            if leaf_script is None:
                sighash = TaprootSignatureHash(psbt.tx, spent_utxos, SIGHASH_DEFAULT, input_index)
            else:
                sighash = TaprootSignatureHash(psbt.tx, spent_utxos, SIGHASH_DEFAULT, input_index,
                                               scriptpath=True, script=leaf_script)
            input_sighashes.add(sighash)
        assert len(input_sighashes) == 1
        sighashes.append(input_sighashes.pop())
    return sighashes


def test_sign_psbt_musig2_prenonces_keypath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                            test_name: str, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = PSBT()
    psbt.deserialize(KEYPATH_PSBT_B64)

    signer_1 = PrenonceMusig2Cosigner(0, client, wallet_policy, wallet_hmac, navigator=navigator, testname=test_name,
                                      instructions=sign_psbt_instruction_approve(
                                          firmware, save_screenshot=False, has_spend_from_wallet=True,
                                          has_feewarning=True))
    signer_2 = HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], KEYPATH_SIGHASHES)
    assert psbt.get_musig2_prenonce_j(signer_1.pubkey.pubkey) == 0


def test_sign_psbt_musig2_prenonces_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                               test_name: str, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = scriptpath_wallet_policy(speculos_globals)

    psbt = PSBT()
    psbt.deserialize(SCRIPTPATH_PSBT_B64)

    signer_1 = PrenonceMusig2Cosigner(5, client, wallet_policy, wallet_hmac, navigator=navigator, testname=test_name,
                                      instructions=sign_psbt_instruction_approve(
                                          firmware, save_screenshot=False, has_spend_from_wallet=True))
    signer_2 = HotMusig2Cosigner(wallet_policy, SCRIPTPATH_COSIGNER_2_XPRIV)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], SCRIPTPATH_SIGHASHES)


def test_sign_psbt_musig2_prenonces_multiple_inputs(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                                    test_name: str, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = txmaker.createPsbt(wallet_policy, [100_000, 200_000, 300_000], [550_000], [False])

    signer_1 = PrenonceMusig2Cosigner(0, client, wallet_policy, wallet_hmac, navigator=navigator, testname=test_name,
                                      instructions=sign_psbt_instruction_approve(
                                          firmware, save_screenshot=False, has_spend_from_wallet=True))
    signer_2 = HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], compute_sighashes(wallet_policy, psbt))


def test_sign_psbt_musig2_prenonces_two_musig_in_leaf(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                                      test_name: str, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = register(speculos_globals, WalletPolicy(
        name="Two musig in a leaf",
        descriptor_template="tr(@0/**,and_v(v:pk(musig(@1,@2)/**),pk(musig(@1,@2)/<2;3>/*)))",
        keys_info=[SCRIPTPATH_INTERNAL_XPUB, SCRIPTPATH_COSIGNER_1_XPUB, SCRIPTPATH_COSIGNER_2_XPUB]
    ))

    psbt = txmaker.createPsbt(wallet_policy, [100_000, 200_000], [250_000], [False])

    signer_1 = PrenonceMusig2Cosigner(0, client, wallet_policy, wallet_hmac, navigator=navigator, testname=test_name,
                                      instructions=sign_psbt_instruction_approve(
                                          firmware, save_screenshot=False, has_spend_from_wallet=True,
                                          has_feewarning=True))
    signer_2 = HotMusig2Cosigner(wallet_policy, SCRIPTPATH_COSIGNER_2_XPRIV)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], compute_sighashes(wallet_policy, psbt))
