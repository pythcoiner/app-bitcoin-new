from hashlib import sha256
import hmac
from io import BytesIO
from typing import Callable, List, Tuple

import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ledger_bitcoin import Musig2PrenonceBatch, MusigPartialSignature
from ledger_bitcoin.client_command import CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG, ClientCommandCode, ClientCommandInterpreter
from ledger_bitcoin.common import read_varint
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.exception.errors import DenyError
from ledger_bitcoin.merkle import element_hash
from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import WalletPolicy
from ragger_bitcoin import RaggerClient
from test_utils import SpeculosGlobals, bip0327, txmaker
from test_utils.bip0322 import build_bip322_psbt
from test_utils.musig2 import HotMusig2Cosigner, MuSig2KeyPlaceholder, PsbtMusig2Cosigner, TrDescriptorTemplate, aggregate_musig_pubkey, process_placeholder, run_musig2_test
from test_utils.taproot_sighash import SIGHASH_DEFAULT, TaprootSignatureHash

from .instructions import sign_psbt_instruction_approve, sign_psbt_instruction_reject
from .test_musig2_prenonces import reset_musig2_prenonces_instructions
from .test_sign_psbt_musig import KEYPATH_COSIGNER_1_XPUB, KEYPATH_COSIGNER_2_XPRIV, KEYPATH_COSIGNER_2_XPUB, KEYPATH_PSBT_B64, KEYPATH_SIGHASHES, SCRIPTPATH_COSIGNER_1_XPUB, SCRIPTPATH_COSIGNER_2_XPRIV, SCRIPTPATH_COSIGNER_2_XPUB, SCRIPTPATH_INTERNAL_XPUB, SCRIPTPATH_PSBT_B64, SCRIPTPATH_SIGHASHES, LedgerMusig2Cosigner, keypath_wallet_policy, musig_pubnonce_ids, scriptpath_wallet_policy

SW_INCORRECT_DATA = 0x6A80
SW_NOT_SUPPORTED = 0x6A82
SW_INS_NOT_SUPPORTED = 0x6D00
SW_BAD_STATE = 0xB007

# Error codes from error_codes.h
EC_SIGN_PSBT_MUSIG2_PRENONCE_MALFORMED_J = 0x0016
EC_SIGN_PSBT_MUSIG2_PRENONCE_INCONSISTENT_J = 0x0017
EC_SIGN_PSBT_MUSIG2_PRENONCE_NOT_ALLOWED = 0x0018
EC_SIGN_PSBT_MUSIG2_PRENONCE_NO_PUBNONCES = 0x0019
EC_SIGN_PSBT_MUSIG2_PRENONCE_STATE_UNAVAILABLE = 0x001a
EC_SIGN_PSBT_MUSIG2_PRENONCE_J_NOT_AVAILABLE = 0x001b
EC_SIGN_PSBT_MUSIG2_PRENONCE_MISSING_PUBNONCE = 0x001c
EC_SIGN_PSBT_MUSIG2_PRENONCE_PUBNONCE_MISMATCH = 0x001d
EC_SIGN_PSBT_MUSIG2_PRENONCE_COSIGNER_PUBNONCE = 0x001e

PRENONCE_WINDOW_SIZE = 128

PSBT_IN_MUSIG2_PUB_NONCE = 0x1B

# another key of the device, used in a second musig()
OTHER_INTERNAL_XPUB = "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK"


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


def assert_refused(e: ExceptionRAPDU, status: int, error_code: int):
    assert e.status == status
    assert e.data == error_code.to_bytes(2, 'big')


@pytest.fixture
def client_requests(monkeypatch) -> List[bytes]:
    # records every client command requested by the device
    requests: List[bytes] = []
    execute = ClientCommandInterpreter.execute

    def recording_execute(self, hw_response: bytes) -> bytes:
        requests.append(hw_response)
        return execute(self, hw_response)

    monkeypatch.setattr(ClientCommandInterpreter, "execute", recording_execute)
    return requests


def assert_nothing_yielded(client_requests: List[bytes]) -> None:
    assert all(request[0] != ClientCommandCode.YIELD for request in client_requests)


def prenonce_psbt(client: RaggerClient, wallet_policy: WalletPolicy, wallet_hmac: bytes, psbt: PSBT, j: int,
                  cosigner_xpriv: str) -> Tuple[PSBT, List[Musig2PrenonceBatch]]:
    # the psbt with our batch j and the pubnonces of the hot cosigner, ready for a one-round signing
    pubkey = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac).pubkey.pubkey
    batches = get_prenonce_batches(client, wallet_policy, wallet_hmac, pubkey, j, len(psbt.inputs))
    place_prenonces(wallet_policy, psbt, batches)
    HotMusig2Cosigner(wallet_policy, cosigner_xpriv).generate_public_nonces(psbt)
    return psbt, batches


def keypath_psbt() -> PSBT:
    psbt = PSBT()
    psbt.deserialize(KEYPATH_PSBT_B64)
    return psbt


def other_keypath_psbt() -> PSBT:
    # another transaction from the same wallet policy and the same input address
    psbt = keypath_psbt()
    psbt.tx.vout[0].nValue += 1000
    psbt.tx.rehash()
    return psbt


def expect_refused(client: RaggerClient, wallet_policy: WalletPolicy, wallet_hmac: bytes, psbt: PSBT,
                   client_requests: List[bytes], status: int, error_code: int) -> None:
    # the device refuses before the review, without yielding anything
    client_requests.clear()
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet_policy, wallet_hmac)
    assert_refused(e.value, status, error_code)
    assert_nothing_yielded(client_requests)


def replace_own_pubnonces(psbt: PSBT, pubkey: bytes, rand_: bytes) -> None:
    # replaces our pubnonces with different, but still valid, ones
    n_replaced = 0
    for input in psbt.inputs:
        for psbt_key in input.musig2_pub_nonces.keys():
            if psbt_key[0] != pubkey:
                continue
            _, other_pubnonce = bip0327.nonce_gen_internal(
                rand_=rand_, sk=None, pk=pubkey, aggpk=None, msg=None, extra_in=None)
            input.musig2_pub_nonces[psbt_key] = other_pubnonce
            n_replaced += 1
    assert n_replaced > 0


def test_sign_psbt_musig2_prenonces_same_j_twice(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                                 test_name: str, speculos_globals: SpeculosGlobals,
                                                 client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)
    result = client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator, testname=test_name,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True))
    assert len(result) == 1 and isinstance(result[0][1], MusigPartialSignature)

    # the coordinator reuses the same batch on another transaction
    other_psbt = other_keypath_psbt()
    place_prenonces(wallet_policy, other_psbt, batches)
    HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV).generate_public_nonces(other_psbt)
    expect_refused(client, wallet_policy, wallet_hmac, other_psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_J_NOT_AVAILABLE)

    # the same transaction again is refused as well
    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_J_NOT_AVAILABLE)


def test_sign_psbt_musig2_prenonces_j_below_hwm(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, _ = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 3, KEYPATH_COSIGNER_2_XPRIV)
    assert client.advance_musig2_prenonces(4) == 4

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_J_NOT_AVAILABLE)


def test_sign_psbt_musig2_prenonces_j_beyond_window(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                    client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)
    psbt.set_musig2_prenonce_j(batches[0].pk, PRENONCE_WINDOW_SIZE)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_J_NOT_AVAILABLE)


def test_sign_psbt_musig2_prenonces_other_wallet(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                 client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    # same keys and same addresses, but a different wallet policy
    other_wallet_policy, other_wallet_hmac = register(speculos_globals, WalletPolicy(
        name="Musig for my other ears",
        descriptor_template="tr(musig(@1,@0)/**)",
        keys_info=wallet_policy.keys_info
    ))

    psbt, _ = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)

    expect_refused(client, other_wallet_policy, other_wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_PUBNONCE_MISMATCH)


def test_sign_psbt_musig2_prenonces_moved_pubnonce(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                   client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = txmaker.createPsbt(wallet_policy, [100_000, 200_000], [250_000], [False])
    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, psbt, 0, KEYPATH_COSIGNER_2_XPRIV)

    # our pubnonces of the two input positions are swapped
    ids = musig_pubnonce_ids(wallet_policy, psbt)
    key_0 = (batches[0].pk, *ids[(0, 0)])
    key_1 = (batches[0].pk, *ids[(1, 0)])
    pubnonces = psbt.inputs[0].musig2_pub_nonces
    other_pubnonces = psbt.inputs[1].musig2_pub_nonces
    pubnonces[key_0], other_pubnonces[key_1] = other_pubnonces[key_1], pubnonces[key_0]

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_PUBNONCE_MISMATCH)


def test_sign_psbt_musig2_prenonces_tampered_pubnonce(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                      client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)
    replace_own_pubnonces(psbt, batches[0].pk, b'\x42' * 32)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_PUBNONCE_MISMATCH)


def test_sign_psbt_musig2_prenonces_missing_cosigner_pubnonce(client: RaggerClient,
                                                              speculos_globals: SpeculosGlobals,
                                                              client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)
    pubnonces = psbt.inputs[0].musig2_pub_nonces
    for psbt_key in [psbt_key for psbt_key in pubnonces if psbt_key[0] != batches[0].pk]:
        del pubnonces[psbt_key]
    assert len(pubnonces) == 1

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_COSIGNER_PUBNONCE)


def test_sign_psbt_musig2_prenonces_mixed(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                          client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = txmaker.createPsbt(wallet_policy, [100_000, 200_000], [250_000], [False])
    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, psbt, 0, KEYPATH_COSIGNER_2_XPRIV)

    # the second input has no pubnonce of ours
    ids = musig_pubnonce_ids(wallet_policy, psbt)
    del psbt.inputs[1].musig2_pub_nonces[(batches[0].pk, *ids[(1, 0)])]

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_MISSING_PUBNONCE)


def test_sign_psbt_musig2_prenonces_inconsistent_j(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                   client_requests: List[bytes]):
    # two musig() key expressions, each with a different key of ours
    wallet_policy, wallet_hmac = register(speculos_globals, WalletPolicy(
        name="Two keys of ours",
        descriptor_template="tr(@0/**,{pk(musig(@1,@2)/**),pk(musig(@3,@2)/<2;3>/*)})",
        keys_info=[SCRIPTPATH_INTERNAL_XPUB, KEYPATH_COSIGNER_1_XPUB, KEYPATH_COSIGNER_2_XPUB, OTHER_INTERNAL_XPUB]
    ))
    pubkey = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac).pubkey.pubkey

    psbt = txmaker.createPsbt(wallet_policy, [100_000], [50_000], [False])

    # only the first musig() gets its pubnonces and j
    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 1, 0, 1)
    assert batch.pk == pubkey
    place_prenonces(wallet_policy, psbt, [batch])
    HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV).generate_public_nonces(psbt)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_INCONSISTENT_J)


def test_sign_psbt_musig2_prenonces_malformed_j(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)
    j_key = next(key for key in psbt.unknown if key.endswith(batches[0].pk))
    for value in [b'', b'\x00' * 3, b'\x00' * 5]:
        psbt.unknown[j_key] = value
        expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                       SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_MALFORMED_J)


def test_sign_psbt_musig2_prenonces_no_pubnonces(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                                 client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)
    pubkey = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac).pubkey.pubkey

    psbt = keypath_psbt()
    psbt.set_musig2_prenonce_j(pubkey, 0)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_NO_PUBNONCES)


def test_sign_psbt_musig2_prenonces_bip322(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                           client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = build_bip322_psbt(wallet_policy, b"I control this musig address")
    psbt, _ = prenonce_psbt(client, wallet_policy, wallet_hmac, psbt, 0, KEYPATH_COSIGNER_2_XPRIV)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_NOT_SUPPORTED, EC_SIGN_PSBT_MUSIG2_PRENONCE_NOT_ALLOWED)


def test_sign_psbt_musig2_prenonces_no_state(client: RaggerClient, speculos_globals: SpeculosGlobals,
                                             client_requests: List[bytes]):
    # signing never creates the state: a j field before any GET is refused
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)
    pubkey = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac).pubkey.pubkey

    psbt = keypath_psbt()
    HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV).generate_public_nonces(psbt)
    psbt.set_musig2_prenonce_j(pubkey, 0)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_BAD_STATE, EC_SIGN_PSBT_MUSIG2_PRENONCE_STATE_UNAVAILABLE)

    # it is still not created
    with pytest.raises(ExceptionRAPDU) as e:
        client.advance_musig2_prenonces(0)
    assert e.value.status == SW_BAD_STATE


def is_partial_signature_yield(request: bytes) -> bool:
    return request[0] == ClientCommandCode.YIELD and \
        read_varint(BytesIO(request[1:])) == CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG


def fail_client_requests(monkeypatch, should_fail: Callable[[bytes], bool]) -> List[bytes]:
    # answers with an empty, malformed response every client command for which should_fail is true;
    # returns the list of the requests that were answered normally
    requests: List[bytes] = []
    execute = ClientCommandInterpreter.execute

    def failing_execute(self, hw_response: bytes) -> bytes:
        if should_fail(hw_response):
            return b''
        requests.append(hw_response)
        return execute(self, hw_response)

    monkeypatch.setattr(ClientCommandInterpreter, "execute", failing_execute)
    return requests


def test_sign_psbt_musig2_prenonces_rejected(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                             test_name: str, speculos_globals: SpeculosGlobals,
                                             client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, _ = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)

    client_requests.clear()
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator, testname=test_name,
                         instructions=sign_psbt_instruction_reject(firmware, save_screenshot=False))
    assert DeviceException.exc.get(e.value.status) == DenyError
    assert_nothing_yielded(client_requests)

    # the rejection consumed nothing: the same j signs afterwards
    result = client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator, testname=test_name,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True))
    assert len(result) == 1 and isinstance(result[0][1], MusigPartialSignature)


def test_sign_psbt_musig2_prenonces_client_failure_before_commit(navigator: Navigator, firmware: Firmware,
                                                                 client: RaggerClient, test_name: str,
                                                                 speculos_globals: SpeculosGlobals, monkeypatch):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, batches = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)

    # the host fails the lookup of our pubnonce, done while validating, before the review
    aggpk_tweaked, _ = musig_pubnonce_ids(wallet_policy, psbt)[(0, 0)]
    pubnonce_key_hash = element_hash(bytes([PSBT_IN_MUSIG2_PUB_NONCE]) + batches[0].pk + aggpk_tweaked)
    requests = fail_client_requests(
        monkeypatch,
        lambda request: request[0] == ClientCommandCode.GET_MERKLE_LEAF_INDEX and request[-32:] == pubnonce_key_hash)

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet_policy, wallet_hmac)
    assert_refused(e.value, SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_MISSING_PUBNONCE)
    assert_nothing_yielded(requests)

    # j was not consumed: once the host answers, the same j signs
    monkeypatch.undo()
    result = client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator, testname=test_name,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True))
    assert len(result) == 1 and isinstance(result[0][1], MusigPartialSignature)


def test_sign_psbt_musig2_prenonces_abort_after_commit(navigator: Navigator, firmware: Firmware,
                                                       client: RaggerClient, test_name: str,
                                                       speculos_globals: SpeculosGlobals, monkeypatch):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt = txmaker.createPsbt(wallet_policy, [100_000, 200_000], [250_000], [False])
    psbt, _ = prenonce_psbt(client, wallet_policy, wallet_hmac, psbt, 0, KEYPATH_COSIGNER_2_XPRIV)

    # the host fails the first client command after the first partial signature
    yielded_partial_signature = False

    def after_first_partial_signature(request: bytes) -> bool:
        nonlocal yielded_partial_signature
        if yielded_partial_signature:
            return True
        yielded_partial_signature = is_partial_signature_yield(request)
        return False

    requests = fail_client_requests(monkeypatch, after_first_partial_signature)

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator, testname=test_name,
                         instructions=sign_psbt_instruction_approve(
                             firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True))
    assert e.value.status == SW_INCORRECT_DATA
    assert len([request for request in requests if request[0] == ClientCommandCode.YIELD]) == 1

    # j is burned: a retry of the same psbt is refused
    monkeypatch.undo()
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet_policy, wallet_hmac)
    assert_refused(e.value, SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_J_NOT_AVAILABLE)


def test_sign_psbt_musig2_prenonces_regenerated(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                                speculos_globals: SpeculosGlobals, client_requests: List[bytes]):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    psbt, _ = prenonce_psbt(client, wallet_policy, wallet_hmac, keypath_psbt(), 0, KEYPATH_COSIGNER_2_XPRIV)

    navigator.navigate(reset_musig2_prenonces_instructions(firmware, True),
                       screen_change_before_first_instruction=False)

    expect_refused(client, wallet_policy, wallet_hmac, psbt, client_requests,
                   SW_INCORRECT_DATA, EC_SIGN_PSBT_MUSIG2_PRENONCE_PUBNONCE_MISMATCH)


class OneRoundSigningCosigner(PsbtMusig2Cosigner):
    """
    Not a real cosigner: when asked for its pubnonces, it makes the device sign another transaction
    of the same wallet policy in one round. Used to check that this does not interfere with the
    pending two-round session.
    """

    def __init__(self, prenonce_cosigner: PrenonceMusig2Cosigner, psbt: PSBT, cosigner_xpriv: str) -> None:
        super().__init__()
        self.prenonce_cosigner = prenonce_cosigner
        self.psbt = psbt
        self.cosigner_xpriv = cosigner_xpriv

    def get_participant_pubkey(self) -> bip0327.Point:
        return self.prenonce_cosigner.get_participant_pubkey()

    def generate_public_nonces(self, psbt: PSBT) -> None:
        wallet_policy = self.prenonce_cosigner.wallet_policy
        run_musig2_test(wallet_policy, self.psbt,
                        [self.prenonce_cosigner, HotMusig2Cosigner(wallet_policy, self.cosigner_xpriv)],
                        compute_sighashes(wallet_policy, self.psbt))

    def generate_partial_signatures(self, psbt: PSBT) -> None:
        pass


def test_sign_psbt_musig2_prenonces_keep_two_round_session(navigator: Navigator, firmware: Firmware,
                                                           client: RaggerClient, test_name: str,
                                                           speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)
    instructions = sign_psbt_instruction_approve(
        firmware, save_screenshot=False, has_spend_from_wallet=True, has_feewarning=True)

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac, navigator=navigator, testname=test_name,
                                    instructions=instructions)
    one_round = OneRoundSigningCosigner(
        PrenonceMusig2Cosigner(0, client, wallet_policy, wallet_hmac, navigator=navigator, testname=test_name,
                               instructions=instructions),
        other_keypath_psbt(), KEYPATH_COSIGNER_2_XPRIV)
    signer_2 = HotMusig2Cosigner(wallet_policy, KEYPATH_COSIGNER_2_XPRIV)

    # the device executes round 1 of the two-round flow, then signs another transaction in one
    # round, then round 2 of the two-round flow
    run_musig2_test(wallet_policy, keypath_psbt(), [signer_1, one_round, signer_2], KEYPATH_SIGHASHES)
