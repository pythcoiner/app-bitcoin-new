#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_EXTENDED_PUBKEY = 0x00,
    REGISTER_WALLET = 0x02,
    GET_WALLET_ADDRESS = 0x03,
    SIGN_PSBT = 0x04,
    GET_MASTER_FINGERPRINT = 0x05,
#ifdef HAVE_MUSIG2_PRENONCES
    GET_MUSIG2_PRENONCES = 0x06,
    ADVANCE_MUSIG2_PRENONCES = 0x07,
#endif
    SIGN_MESSAGE = 0x10,
} command_e;

// Tags used when yielding different objects with the YIELD client command.
#define CCMD_YIELD_MUSIG_PUBNONCE_TAG         0xffffffff
#define CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG 0xfffffffe
