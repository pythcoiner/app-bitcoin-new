from hashlib import sha256
import hmac
from pathlib import Path
from typing import List, Tuple

import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.firmware.touch.positions import STAX_X_CENTER, FLEX_X_CENTER, APEX_P_X_CENTER, STAX_BUTTON_LOWER_MIDDLE, FLEX_BUTTON_LOWER_MIDDLE, APEX_P_BUTTON_LOWER_MIDDLE
from ragger.navigator import Navigator, NavInsID, NavIns

from ledger_bitcoin import Musig2PrenonceBatch
from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.wallet import WalletPolicy
from ragger_bitcoin import RaggerClient
from test_utils import SpeculosGlobals, bip0327
from test_utils.wallet_policy import aggregate_musig_pubkey

from .test_sign_psbt_musig import KEYPATH_COSIGNER_1_XPUB, KEYPATH_COSIGNER_2_XPUB, SCRIPTPATH_INTERNAL_XPUB, keypath_wallet_policy, scriptpath_wallet_policy

SW_INCORRECT_DATA = 0x6A80
SW_NOT_SUPPORTED = 0x6A82
SW_INS_NOT_SUPPORTED = 0x6D00
SW_BAD_STATE = 0xB007
SW_SIGNATURE_FAIL = 0xB008

# Error codes from error_codes.h
EC_GET_MUSIG2_PRENONCES_MISSING_HMAC = 0x0000
EC_GET_MUSIG2_PRENONCES_NOT_TAPROOT = 0x0001
EC_GET_MUSIG2_PRENONCES_NOT_INTERNAL_MUSIG = 0x0002
EC_GET_MUSIG2_PRENONCES_INVALID_INPUT_RANGE = 0x0003
EC_GET_MUSIG2_PRENONCES_J_NOT_AVAILABLE = 0x0004
EC_ADVANCE_MUSIG2_PRENONCES_STATE_UNAVAILABLE = 0x0000

PRENONCE_WINDOW_SIZE = 128

tests_root: Path = Path(__file__).parent


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


def assert_refused(e: ExceptionRAPDU, status: int, error_code: int):
    assert e.status == status
    assert e.data == error_code.to_bytes(2, 'big')


def test_get_musig2_prenonces(client: RaggerClient, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 3)

    assert batch.j == 0
    assert batch.k == 0
    assert batch.pk == ExtendedKey.deserialize(
        KEYPATH_COSIGNER_1_XPUB[KEYPATH_COSIGNER_1_XPUB.index(']') + 1:]).pubkey
    _, keyagg_ctx = aggregate_musig_pubkey([KEYPATH_COSIGNER_1_XPUB, KEYPATH_COSIGNER_2_XPUB])
    assert batch.agg_pk == bip0327.cbytes(keyagg_ctx.Q)
    assert batch.hwm == 0
    assert [i for i, _ in batch.pubnonces] == [0, 1, 2]
    for _, pubnonce in batch.pubnonces:
        assert len(pubnonce) == 66
        bip0327.cpoint(pubnonce[:33])
        bip0327.cpoint(pubnonce[33:])
    assert len({pubnonce for _, pubnonce in batch.pubnonces}) == 3

    # the same request gives the same pubnonces
    assert client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 3) == batch

    # the pubnonce depends on the input position, not on the position in the request
    other = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 1, 1)
    assert other.pubnonces == [batch.pubnonces[1]]


def test_get_musig2_prenonces_differ_by_j_and_k(client: RaggerClient, speculos_globals: SpeculosGlobals):
    # the same musig() twice: k differs, the untweaked aggregate key is the same
    wallet_policy, wallet_hmac = register(speculos_globals, WalletPolicy(
        name="Two musig",
        descriptor_template="tr(musig(@0,@1)/**,pk(musig(@0,@1)/<2;3>/*))",
        keys_info=[KEYPATH_COSIGNER_1_XPUB, KEYPATH_COSIGNER_2_XPUB]
    ))

    batch_j0_k0 = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 2)
    batch_j1_k0 = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 1, 0, 0, 2)
    batch_j0_k1 = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 1, 0, 2)

    assert batch_j0_k1.agg_pk == batch_j0_k0.agg_pk
    pubnonces = [pubnonce for batch in [batch_j0_k0, batch_j1_k0, batch_j0_k1]
                 for _, pubnonce in batch.pubnonces]
    assert len(set(pubnonces)) == 6


def test_musig2_prenonce_batch_serialization():
    batch = Musig2PrenonceBatch(
        j=0x01020304,
        k=5,
        pk=b'\x02' + b'\x11' * 32,
        agg_pk=b'\x03' + b'\x22' * 32,
        hwm=7,
        pubnonces=[(0, b'\x33' * 66), (9, b'\x44' * 66)]
    )
    serialized = batch.serialize()
    assert serialized == b''.join([
        b'MPNB\x01',
        bytes.fromhex("01020304"),
        bytes.fromhex("00000005"),
        b'\x02' + b'\x11' * 32,
        b'\x03' + b'\x22' * 32,
        bytes.fromhex("00000007"),
        b'\x02',
        bytes.fromhex("00000000") + b'\x33' * 66,
        bytes.fromhex("00000009") + b'\x44' * 66,
    ])
    assert Musig2PrenonceBatch.deserialize(serialized) == batch

    with pytest.raises(ValueError):
        Musig2PrenonceBatch.deserialize(b'MPNX' + serialized[4:])
    with pytest.raises(ValueError):
        Musig2PrenonceBatch.deserialize(serialized + b'\x00')


def test_get_musig2_prenonces_wrong_hmac(client: RaggerClient, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_musig2_prenonces(wallet_policy, b'\0' * 32, 0, 0, 0, 1)
    assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_MISSING_HMAC)

    wrong_hmac = bytes([wallet_hmac[0] ^ 1]) + wallet_hmac[1:]
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_musig2_prenonces(wallet_policy, wrong_hmac, 0, 0, 0, 1)
    assert e.value.status == SW_SIGNATURE_FAIL


def test_get_musig2_prenonces_not_internal_musig(client: RaggerClient, speculos_globals: SpeculosGlobals):
    # key expression 0 is a plain key, 1 is the musig(), there is no key expression 2
    wallet_policy, wallet_hmac = scriptpath_wallet_policy(speculos_globals)
    client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 1, 0, 1)
    for k in [0, 2]:
        with pytest.raises(ExceptionRAPDU) as e:
            client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, k, 0, 1)
        assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_NOT_INTERNAL_MUSIG)

    # a musig() with no internal key
    wallet_policy, wallet_hmac = register(speculos_globals, WalletPolicy(
        name="External musig",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[KEYPATH_COSIGNER_2_XPUB, SCRIPTPATH_INTERNAL_XPUB]
    ))
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 1)
    assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_NOT_INTERNAL_MUSIG)

    wallet_policy, wallet_hmac = register(speculos_globals, WalletPolicy(
        name="Not taproot",
        descriptor_template="wsh(pk(@0/**))",
        keys_info=[KEYPATH_COSIGNER_1_XPUB]
    ))
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 1)
    assert_refused(e.value, SW_NOT_SUPPORTED, EC_GET_MUSIG2_PRENONCES_NOT_TAPROOT)


def test_get_musig2_prenonces_input_range(client: RaggerClient, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    for input_start, input_count in [(0, 0), (0, 33), (0xFFFFFFFF, 2), (0xFFFFFFE1, 32)]:
        with pytest.raises(ExceptionRAPDU) as e:
            client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, input_start, input_count)
        assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_INVALID_INPUT_RANGE)

    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 32)
    assert [i for i, _ in batch.pubnonces] == list(range(32))
    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0xFFFFFFE0, 32)
    assert [i for i, _ in batch.pubnonces] == list(range(0xFFFFFFE0, 0x100000000))


def test_musig2_prenonces_window(client: RaggerClient, speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    # ADVANCE does not create the state
    with pytest.raises(ExceptionRAPDU) as e:
        client.advance_musig2_prenonces(10)
    assert_refused(e.value, SW_BAD_STATE, EC_ADVANCE_MUSIG2_PRENONCES_STATE_UNAVAILABLE)

    # GET creates the state, with an empty window
    assert client.get_musig2_prenonces(wallet_policy, wallet_hmac, PRENONCE_WINDOW_SIZE - 1, 0, 0, 1).hwm == 0
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_musig2_prenonces(wallet_policy, wallet_hmac, PRENONCE_WINDOW_SIZE, 0, 0, 1)
    assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_J_NOT_AVAILABLE)

    batch_j10 = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10, 0, 0, 1)

    assert client.advance_musig2_prenonces(10) == 10

    for j in [0, 9, 10 + PRENONCE_WINDOW_SIZE]:
        with pytest.raises(ExceptionRAPDU) as e:
            client.get_musig2_prenonces(wallet_policy, wallet_hmac, j, 0, 0, 1)
        assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_J_NOT_AVAILABLE)

    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10, 0, 0, 1)
    assert batch.hwm == 10
    assert batch.pubnonces == batch_j10.pubnonces
    client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10 + PRENONCE_WINDOW_SIZE - 1, 0, 0, 1)

    # ADVANCE never lowers hwm
    assert client.advance_musig2_prenonces(5) == 10
    assert client.advance_musig2_prenonces(0) == 10
    with pytest.raises(ExceptionRAPDU) as e:
        client.get_musig2_prenonces(wallet_policy, wallet_hmac, 9, 0, 0, 1)
    assert_refused(e.value, SW_INCORRECT_DATA, EC_GET_MUSIG2_PRENONCES_J_NOT_AVAILABLE)


def reset_musig2_prenonces_instructions(firmware: Firmware, confirm: bool) -> List[NavIns]:
    # opens the settings, selects the reset entry on the second settings page, then confirms or cancels
    if firmware.device.startswith("nano"):
        open_dialog = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK,
                       NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK]
        return open_dialog + ([NavInsID.BOTH_CLICK] if confirm else [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK])

    # USE_CASE_CHOICE_REJECT misses the centered cancel button on apex_p, so it is touched directly
    if firmware.device == "stax":
        bar_pos, cancel_pos = (STAX_X_CENTER, 135), STAX_BUTTON_LOWER_MIDDLE
    elif firmware.device == "flex":
        bar_pos, cancel_pos = (FLEX_X_CENTER, 135), FLEX_BUTTON_LOWER_MIDDLE
    else:  # apex_p, apex_m
        bar_pos, cancel_pos = (APEX_P_X_CENTER, 90), APEX_P_BUTTON_LOWER_MIDDLE
    return [
        NavInsID.USE_CASE_HOME_SETTINGS,
        NavInsID.USE_CASE_SETTINGS_NEXT,
        NavIns(NavInsID.TOUCH, bar_pos),
        NavInsID.USE_CASE_CHOICE_CONFIRM if confirm else NavIns(NavInsID.TOUCH, cancel_pos),
    ]


def test_musig2_prenonces_reset(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str,
                                speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10, 0, 0, 2)
    assert client.advance_musig2_prenonces(5) == 5

    navigator.navigate_and_compare(tests_root, test_name,
                                   reset_musig2_prenonces_instructions(firmware, True),
                                   screen_change_before_first_instruction=False)

    # the window is empty, and the same j gives other pubnonces
    new_batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10, 0, 0, 2)
    assert new_batch.hwm == 0
    assert {pubnonce for _, pubnonce in new_batch.pubnonces}.isdisjoint(
        {pubnonce for _, pubnonce in batch.pubnonces})
    client.get_musig2_prenonces(wallet_policy, wallet_hmac, 0, 0, 0, 1)


def test_musig2_prenonces_reset_cancel(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                       speculos_globals: SpeculosGlobals):
    wallet_policy, wallet_hmac = keypath_wallet_policy(speculos_globals)

    batch = client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10, 0, 0, 2)
    assert client.advance_musig2_prenonces(5) == 5

    navigator.navigate(reset_musig2_prenonces_instructions(firmware, False),
                       screen_change_before_first_instruction=False)

    assert client.get_musig2_prenonces(wallet_policy, wallet_hmac, 10, 0, 0, 2) == Musig2PrenonceBatch(
        j=10, k=0, pk=batch.pk, agg_pk=batch.agg_pk, hwm=5, pubnonces=batch.pubnonces)
