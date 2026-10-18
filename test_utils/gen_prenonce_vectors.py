"""Prints the test vectors of unit-tests/test_musig_prenonce.c, computed with the BIP-327
reference implementation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bip0327 import cbytes, individual_pk, key_agg, key_sort, nonce_gen_internal, tagged_hash  # noqa: E402

NONCE_INIT = bytes.fromhex("01" * 32)
WALLET_ID = bytes.fromhex("03" * 32)
SK = bytes.fromhex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671")
COSIGNER_PK = bytes.fromhex("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")

CASES = [
    (0, 0, 0),
    (1, 0, 0),
    (0, 1, 0),
    (0, 0, 1),
    (0x12345678, 3, 2),
    (0xFFFFFFFE, 0xFFFFFFFF, 7),
]


def ser32(n: int) -> bytes:
    return n.to_bytes(4, 'big')


def main():
    pk = individual_pk(SK)
    agg_pk = cbytes(key_agg(key_sort([pk, COSIGNER_PK])).Q)
    print(f'#define PRENONCE_PK     "{pk.hex().upper()}"')
    print(f'#define PRENONCE_AGG_PK "{agg_pk.hex().upper()}"')
    for j, i, k in CASES:
        rand_ = tagged_hash('MuSig2Prenonce',
                            NONCE_INIT + ser32(j) + ser32(i) + ser32(k) + WALLET_ID + pk + agg_pk)
        secnonce, pubnonce = nonce_gen_internal(rand_, SK, pk, agg_pk[1:], None, ser32(j))
        print('    {')
        print(f'        0x{j:08X}, 0x{i:08X}, {k},')
        print(f'        "{bytes(secnonce).hex().upper()}",')
        print(f'        "{pubnonce.hex().upper()}",')
        print('    },')


if __name__ == '__main__':
    main()
