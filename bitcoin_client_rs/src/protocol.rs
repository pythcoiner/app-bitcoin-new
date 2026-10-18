//! This module contains types that are specific to the Ledger Bitcoin application protocol.

use bitcoin::{
    consensus::encode::{
        deserialize_partial, serialize, Decodable, Encodable, Error as EncodeError,
    },
    hashes::Hash,
    io::{Read, Write},
    taproot::TapLeafHash,
    PublicKey,
};

use crate::psbt::{PartialSignature, PartialSignatureError};

/// A variable-length unsigned integer using the same wire encoding as
/// Bitcoin's `CompactSize`, but without the upper-bound limit enforced by the
/// `bitcoin` crate's [`VarInt`](bitcoin::consensus::encode::VarInt).
///
/// The Ledger protocol reuses the CompactSize encoding for tag values (e.g.
/// `0xFFFFFFFF`) that exceed `MAX_COMPACT_SIZE`.  This type can be used for
/// both serialization and deserialization of any `u64` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UncheckedVarInt(pub u64);

impl Encodable for UncheckedVarInt {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(w)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                0xFDu8.consensus_encode(w)?;
                (self.0 as u16).consensus_encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.consensus_encode(w)?;
                (self.0 as u32).consensus_encode(w)?;
                Ok(5)
            }
            _ => {
                0xFFu8.consensus_encode(w)?;
                self.0.consensus_encode(w)?;
                Ok(9)
            }
        }
    }
}

impl Decodable for UncheckedVarInt {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, EncodeError> {
        let n = u8::consensus_decode(r)?;
        match n {
            0xFF => {
                let x = u64::consensus_decode(r)?;
                if x < 0x1_0000_0000 {
                    Err(EncodeError::NonMinimalVarInt)
                } else {
                    Ok(UncheckedVarInt(x))
                }
            }
            0xFE => {
                let x = u32::consensus_decode(r)?;
                if x < 0x10000 {
                    Err(EncodeError::NonMinimalVarInt)
                } else {
                    Ok(UncheckedVarInt(x as u64))
                }
            }
            0xFD => {
                let x = u16::consensus_decode(r)?;
                if x < 0xFD {
                    Err(EncodeError::NonMinimalVarInt)
                } else {
                    Ok(UncheckedVarInt(x as u64))
                }
            }
            n => Ok(UncheckedVarInt(n as u64)),
        }
    }
}

/// Tag yielded by the device to introduce a MuSig2 pubnonce payload.
pub const CCMD_YIELD_MUSIG_PUBNONCE_TAG: u64 = 0xFFFFFFFF;
/// Tag yielded by the device to introduce a MuSig2 partial-signature payload.
pub const CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG: u64 = 0xFFFFFFFE;

/// A MuSig2 public nonce yielded by the device during the first round of a
/// MuSig2 signing session, as specified in BIP-373.
#[derive(Debug, Clone)]
pub struct MusigPubNonce {
    /// The 33-byte compressed pubkey of this participant.
    pub participant_pubkey: PublicKey,
    /// The 33-byte compressed aggregate pubkey.
    pub aggregate_pubkey: PublicKey,
    /// The tapleaf hash, if signing for a tapscript; `None` otherwise.
    pub tapleaf_hash: Option<TapLeafHash>,
    /// The 66-byte pubnonce.
    pub pubnonce: [u8; 66],
}

/// A MuSig2 partial signature yielded by the device during the second round of
/// a MuSig2 signing session, as specified in BIP-373
///
/// Note: not to be confused with [`PartialSignature`], which represents a
/// regular ECDSA or Schnorr signature for a single input.
#[derive(Debug, Clone)]
pub struct MusigPartialSignature {
    /// The 33-byte compressed pubkey of this participant.
    pub participant_pubkey: PublicKey,
    /// The 33-byte compressed aggregate pubkey.
    pub aggregate_pubkey: PublicKey,
    /// The tapleaf hash, if signing for a tapscript; `None` otherwise.
    pub tapleaf_hash: Option<TapLeafHash>,
    /// The 32-byte partial signature for this participant.
    pub partial_signature: [u8; 32],
}

/// An object yielded by the device while signing a PSBT.
///
/// The variants cover the different kinds of payload the device can produce.
/// The enum is `#[non_exhaustive]`: callers must include a wildcard arm so that
/// new payload kinds introduced in future protocol versions do not cause
/// compilation failures in existing code.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum SignPsbtYieldedObject {
    /// A regular partial signature for a PSBT input.
    Partial(PartialSignature),
    /// A MuSig2 public nonce (round 1).
    MusigPubNonce(MusigPubNonce),
    /// A MuSig2 partial signature (round 2).
    MusigPartialSignature(MusigPartialSignature),
    /// An unknown payload with an unrecognized tag; the original bytes are included for reference.
    Unknown(Vec<u8>),
}

/// Parses a single payload yielded by the device during `sign_psbt`.
///
/// On success returns the input index together with the decoded object.
pub fn parse_sign_psbt_yielded(
    data: &[u8],
) -> Result<(usize, SignPsbtYieldedObject), PartialSignatureError> {
    let (UncheckedVarInt(tag), i): (UncheckedVarInt, usize) =
        deserialize_partial(data).map_err(|_| PartialSignatureError::InvalidLength)?;

    match tag {
        CCMD_YIELD_MUSIG_PUBNONCE_TAG => {
            let (UncheckedVarInt(input_index), j): (UncheckedVarInt, usize) =
                deserialize_partial(&data[i..])
                    .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            // Layout: 66-byte pubnonce || 33-byte participant pubkey ||
            //         33-byte aggregate pubkey || optional 32-byte tapleaf hash.
            if rest.len() != 132 && rest.len() != 164 {
                return Err(PartialSignatureError::InvalidLength);
            }
            let mut pubnonce = [0u8; 66];
            pubnonce.copy_from_slice(&rest[0..66]);
            let participant_pubkey =
                PublicKey::from_slice(&rest[66..99]).map_err(PartialSignatureError::PubKey)?;
            let aggregate_pubkey =
                PublicKey::from_slice(&rest[99..132]).map_err(PartialSignatureError::PubKey)?;
            let tapleaf_hash = if rest.len() == 164 {
                Some(
                    TapLeafHash::from_slice(&rest[132..164])
                        .map_err(PartialSignatureError::TapLeaf)?,
                )
            } else {
                None
            };
            Ok((
                input_index as usize,
                SignPsbtYieldedObject::MusigPubNonce(MusigPubNonce {
                    participant_pubkey,
                    aggregate_pubkey,
                    tapleaf_hash,
                    pubnonce,
                }),
            ))
        }
        CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG => {
            let (UncheckedVarInt(input_index), j): (UncheckedVarInt, usize) =
                deserialize_partial(&data[i..])
                    .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            // Layout: 32-byte partial signature || 33-byte participant pubkey ||
            //         33-byte aggregate pubkey || optional 32-byte tapleaf hash.
            if rest.len() != 98 && rest.len() != 130 {
                return Err(PartialSignatureError::InvalidLength);
            }
            let mut partial_signature = [0u8; 32];
            partial_signature.copy_from_slice(&rest[0..32]);
            let participant_pubkey =
                PublicKey::from_slice(&rest[32..65]).map_err(PartialSignatureError::PubKey)?;
            let aggregate_pubkey =
                PublicKey::from_slice(&rest[65..98]).map_err(PartialSignatureError::PubKey)?;
            let tapleaf_hash = if rest.len() == 130 {
                Some(
                    TapLeafHash::from_slice(&rest[98..130])
                        .map_err(PartialSignatureError::TapLeaf)?,
                )
            } else {
                None
            };
            Ok((
                input_index as usize,
                SignPsbtYieldedObject::MusigPartialSignature(MusigPartialSignature {
                    participant_pubkey,
                    aggregate_pubkey,
                    tapleaf_hash,
                    partial_signature,
                }),
            ))
        }
        // Reserved tag range used by the protocol for non-input-index payloads.
        // Tags in this range that are not explicitly handled above are unknown to this client version, and reserved
        // for future use.
        tag_value if tag_value >= 0x80000000 => {
            // Future tags are expected to follow the same layout, using the first varint to refer to the input index
            let (UncheckedVarInt(input_index), j): (UncheckedVarInt, usize) =
                deserialize_partial(&data[i..])
                    .map_err(|_| PartialSignatureError::InvalidLength)?;
            let rest = &data[i + j..];
            Ok((
                input_index as usize,
                SignPsbtYieldedObject::Unknown(rest.to_vec()),
            ))
        }
        // Otherwise the leading varint is the input index and the remainder is a regular partial signature.
        // These are the only payloads that were used in protocol versions prior to the introduction of the tags.
        _ => {
            let input_index = tag as usize;
            let ps = PartialSignature::from_slice(&data[i..])?;
            Ok((input_index, SignPsbtYieldedObject::Partial(ps)))
        }
    }
}

/// Magic of the MPNB binary form of a [`Musig2PrenonceBatch`].
pub const MUSIG2_PRENONCE_BATCH_MAGIC: &[u8; 4] = b"MPNB";
/// Version of the MPNB binary form.
pub const MUSIG2_PRENONCE_BATCH_VERSION: u8 = 1;

/// A batch of pre-issued MuSig2 pubnonces returned by `get_musig2_prenonces`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Musig2PrenonceBatch {
    /// The index of the batch, that a single signing call can use.
    pub j: u32,
    /// The index of the musig() key expression in the descriptor template.
    pub k: u32,
    /// The 33-byte compressed participant pubkey of the device.
    pub participant_pubkey: [u8; 33],
    /// The 33-byte compressed aggregate pubkey of the musig(), before any tweak.
    pub aggregate_pubkey: [u8; 33],
    /// The high-water mark of the device when the batch was issued.
    pub hwm: u32,
    /// The (input position, 66-byte pubnonce) pairs.
    pub pubnonces: Vec<(u32, [u8; 66])>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Musig2PrenonceBatchError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
}

impl Musig2PrenonceBatch {
    /// Builds the batch from the response and the yielded payloads of GET_MUSIG2_PRENONCES.
    pub(crate) fn from_response(
        j: u32,
        k: u32,
        response: &[u8],
        yielded: &[Vec<u8>],
    ) -> Result<Self, Musig2PrenonceBatchError> {
        // response: participant pubkey || aggregate pubkey || hwm
        let mut d = response;
        let participant_pubkey = take(&mut d)?;
        let aggregate_pubkey = take(&mut d)?;
        let hwm = u32::from_be_bytes(take(&mut d)?);
        if !d.is_empty() {
            return Err(Musig2PrenonceBatchError::InvalidLength);
        }
        let pubnonces = yielded
            .iter()
            .map(|payload| {
                let mut d = payload.as_slice();
                let entry = take_pubnonce(&mut d)?;
                if !d.is_empty() {
                    return Err(Musig2PrenonceBatchError::InvalidLength);
                }
                Ok(entry)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            j,
            k,
            participant_pubkey,
            aggregate_pubkey,
            hwm,
            pubnonces,
        })
    }

    /// Serializes the batch in the MPNB binary form, for files and QR codes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = MUSIG2_PRENONCE_BATCH_MAGIC.to_vec();
        data.push(MUSIG2_PRENONCE_BATCH_VERSION);
        data.extend_from_slice(&self.j.to_be_bytes());
        data.extend_from_slice(&self.k.to_be_bytes());
        data.extend_from_slice(&self.participant_pubkey);
        data.extend_from_slice(&self.aggregate_pubkey);
        data.extend_from_slice(&self.hwm.to_be_bytes());
        data.extend(serialize(&UncheckedVarInt(self.pubnonces.len() as u64)));
        for (i, pubnonce) in &self.pubnonces {
            data.extend_from_slice(&i.to_be_bytes());
            data.extend_from_slice(pubnonce);
        }
        data
    }

    /// Parses a batch in the MPNB binary form.
    pub fn deserialize(data: &[u8]) -> Result<Self, Musig2PrenonceBatchError> {
        let mut d = data;
        if &take::<4>(&mut d)? != MUSIG2_PRENONCE_BATCH_MAGIC {
            return Err(Musig2PrenonceBatchError::InvalidMagic);
        }
        if take::<1>(&mut d)?[0] != MUSIG2_PRENONCE_BATCH_VERSION {
            return Err(Musig2PrenonceBatchError::UnsupportedVersion);
        }
        let j = u32::from_be_bytes(take(&mut d)?);
        let k = u32::from_be_bytes(take(&mut d)?);
        let participant_pubkey = take(&mut d)?;
        let aggregate_pubkey = take(&mut d)?;
        let hwm = u32::from_be_bytes(take(&mut d)?);
        let UncheckedVarInt(n) = UncheckedVarInt::consensus_decode(&mut d)
            .map_err(|_| Musig2PrenonceBatchError::InvalidLength)?;
        let pubnonces = (0..n)
            .map(|_| take_pubnonce(&mut d))
            .collect::<Result<_, _>>()?;
        if !d.is_empty() {
            return Err(Musig2PrenonceBatchError::InvalidLength);
        }
        Ok(Self {
            j,
            k,
            participant_pubkey,
            aggregate_pubkey,
            hwm,
            pubnonces,
        })
    }
}

/// Reads `N` bytes, advancing `d` past them.
fn take<const N: usize>(d: &mut &[u8]) -> Result<[u8; N], Musig2PrenonceBatchError> {
    if d.len() < N {
        return Err(Musig2PrenonceBatchError::InvalidLength);
    }
    let mut bytes = [0u8; N];
    bytes.copy_from_slice(&d[..N]);
    *d = &d[N..];
    Ok(bytes)
}

/// Reads one `ser32(i) || pubnonce` entry.
fn take_pubnonce(d: &mut &[u8]) -> Result<(u32, [u8; 66]), Musig2PrenonceBatchError> {
    let i = u32::from_be_bytes(take(d)?);
    Ok((i, take(d)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use hex_literal::hex;

    // Arbitrary valid compressed secp256k1 pubkey (no special meaning).
    const PUBKEY: [u8; 33] =
        hex!("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    // x-only version of the same pubkey (drops the 0x03 prefix).
    const XONLY: [u8; 32] =
        hex!("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
    // 32-byte tapleaf hash placeholder (any 32 bytes are accepted by from_slice).
    const TAPLEAF: [u8; 32] =
        hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    fn parse_ok(payload: &[u8]) -> (usize, SignPsbtYieldedObject) {
        match parse_sign_psbt_yielded(payload) {
            Ok(v) => v,
            Err(_) => panic!("parse_sign_psbt_yielded returned an unexpected error"),
        }
    }

    #[test]
    fn parse_legacy_partial_taproot_no_tapleaf() {
        // Layout (untagged, used by protocol versions <= 2.1):
        //   varint(input_index) || key_augment_len(=32) || 32-byte x-only pk || 64-byte schnorr sig
        let mut payload = serialize(&UncheckedVarInt(3));
        payload.push(32);
        payload.extend(XONLY);
        payload.extend([0xAAu8; 64]);

        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 3);
        match obj {
            SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(_, tlh, _)) => {
                assert!(tlh.is_none());
            }
            other => panic!("expected TapScriptSig without tapleaf, got {:?}", other),
        }
    }

    fn build_musig_pubnonce(input_index: u64, with_tapleaf: bool) -> Vec<u8> {
        let mut payload = serialize(&UncheckedVarInt(CCMD_YIELD_MUSIG_PUBNONCE_TAG));
        payload.extend(serialize(&UncheckedVarInt(input_index)));
        payload.extend([0xAAu8; 66]); // pubnonce
        payload.extend(PUBKEY); // participant pk (33)
        payload.extend(PUBKEY); // aggregate pk  (33)
        if with_tapleaf {
            payload.extend(TAPLEAF);
        }
        payload
    }

    #[test]
    fn parse_musig_pubnonce_without_tapleaf() {
        let payload = build_musig_pubnonce(7, false);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 7);
        match obj {
            SignPsbtYieldedObject::MusigPubNonce(n) => {
                assert!(n.tapleaf_hash.is_none());
                assert_eq!(n.pubnonce, [0xAAu8; 66]);
                assert_eq!(n.participant_pubkey.to_bytes(), PUBKEY);
                assert_eq!(n.aggregate_pubkey.to_bytes(), PUBKEY);
            }
            other => panic!("expected MusigPubNonce, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_pubnonce_with_tapleaf() {
        let payload = build_musig_pubnonce(0, true);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 0);
        match obj {
            SignPsbtYieldedObject::MusigPubNonce(n) => {
                let tlh = n.tapleaf_hash.expect("tapleaf hash should be present");
                assert_eq!(tlh.to_byte_array(), TAPLEAF);
            }
            other => panic!("expected MusigPubNonce, got {:?}", other),
        }
    }

    fn build_musig_partial_sig(input_index: u64, with_tapleaf: bool) -> Vec<u8> {
        let mut payload = serialize(&UncheckedVarInt(CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG));
        payload.extend(serialize(&UncheckedVarInt(input_index)));
        payload.extend([0xBBu8; 32]); // partial signature
        payload.extend(PUBKEY); // participant pk (33)
        payload.extend(PUBKEY); // aggregate pk  (33)
        if with_tapleaf {
            payload.extend(TAPLEAF);
        }
        payload
    }

    #[test]
    fn parse_musig_partial_signature_without_tapleaf() {
        let payload = build_musig_partial_sig(2, false);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 2);
        match obj {
            SignPsbtYieldedObject::MusigPartialSignature(s) => {
                assert!(s.tapleaf_hash.is_none());
                assert_eq!(s.partial_signature, [0xBBu8; 32]);
                assert_eq!(s.participant_pubkey.to_bytes(), PUBKEY);
                assert_eq!(s.aggregate_pubkey.to_bytes(), PUBKEY);
            }
            other => panic!("expected MusigPartialSignature, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_partial_signature_with_tapleaf() {
        let payload = build_musig_partial_sig(42, true);
        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 42);
        match obj {
            SignPsbtYieldedObject::MusigPartialSignature(s) => {
                let tlh = s.tapleaf_hash.expect("tapleaf hash should be present");
                assert_eq!(tlh.to_byte_array(), TAPLEAF);
            }
            other => panic!("expected MusigPartialSignature, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_reserved_tag() {
        // Any tag in the reserved range (>= 0x80000000) that this client version does
        // not explicitly handle must surface as `Unknown` while preserving input_index
        // and the trailing payload verbatim.
        const UNKNOWN_TAG: u64 = 0x89AB_CDEF;
        let trailer = hex!("deadbeef");

        let mut payload = serialize(&UncheckedVarInt(UNKNOWN_TAG));
        payload.extend(serialize(&UncheckedVarInt(11)));
        payload.extend(&trailer);

        let (idx, obj) = parse_ok(&payload);
        assert_eq!(idx, 11);
        match obj {
            SignPsbtYieldedObject::Unknown(bytes) => assert_eq!(bytes, trailer),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn parse_musig_pubnonce_wrong_trailer_length_is_error() {
        // Drop one byte from the aggregate pubkey to make the trailer length invalid
        // (133 bytes instead of 132 or 164).
        let mut payload = build_musig_pubnonce(0, false);
        payload.push(0x00);
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_partial_signature_wrong_trailer_length_is_error() {
        let mut payload = build_musig_partial_sig(0, false);
        payload.push(0x00);
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_pubnonce_truncated_input_is_error() {
        // Truncate so the participant pubkey is missing entirely.
        let full = build_musig_pubnonce(0, false);
        // tag(5) + input_index(1) + pubnonce(66) = 72 bytes; cut everything after that.
        let truncated = &full[..72];
        assert!(matches!(
            parse_sign_psbt_yielded(truncated),
            Err(PartialSignatureError::InvalidLength)
        ));
    }

    #[test]
    fn parse_musig_pubnonce_invalid_participant_pubkey_is_error() {
        // Replace the participant pubkey (33 bytes after the 66-byte nonce) with all
        // zeros, which is not a valid encoded compressed pubkey.
        let mut payload = build_musig_pubnonce(0, false);
        // tag(5 bytes for 0xFFFFFFFF) + input_index(1) + pubnonce(66) = 72.
        let pubkey_offset = 72;
        for b in &mut payload[pubkey_offset..pubkey_offset + 33] {
            *b = 0x00;
        }
        assert!(matches!(
            parse_sign_psbt_yielded(&payload),
            Err(PartialSignatureError::PubKey(_))
        ));
    }

    fn prenonce_batch() -> Musig2PrenonceBatch {
        let mut participant_pubkey = [0x11u8; 33];
        participant_pubkey[0] = 0x02;
        let mut aggregate_pubkey = [0x22u8; 33];
        aggregate_pubkey[0] = 0x03;
        Musig2PrenonceBatch {
            j: 0x01020304,
            k: 5,
            participant_pubkey,
            aggregate_pubkey,
            hwm: 7,
            pubnonces: vec![(0, [0x33u8; 66]), (9, [0x44u8; 66])],
        }
    }

    #[test]
    fn musig2_prenonce_batch_serialization() {
        let batch = prenonce_batch();
        let serialized = batch.serialize();

        let mut expected = b"MPNB\x01".to_vec();
        expected.extend(hex!("01020304"));
        expected.extend(hex!("00000005"));
        expected.push(0x02);
        expected.extend([0x11u8; 32]);
        expected.push(0x03);
        expected.extend([0x22u8; 32]);
        expected.extend(hex!("00000007"));
        expected.push(0x02);
        expected.extend(hex!("00000000"));
        expected.extend([0x33u8; 66]);
        expected.extend(hex!("00000009"));
        expected.extend([0x44u8; 66]);
        assert_eq!(serialized, expected);

        assert_eq!(Musig2PrenonceBatch::deserialize(&serialized), Ok(batch));

        let mut wrong_magic = serialized.clone();
        wrong_magic[3] = b'X';
        assert_eq!(
            Musig2PrenonceBatch::deserialize(&wrong_magic),
            Err(Musig2PrenonceBatchError::InvalidMagic)
        );
        let mut wrong_version = serialized.clone();
        wrong_version[4] = 0x02;
        assert_eq!(
            Musig2PrenonceBatch::deserialize(&wrong_version),
            Err(Musig2PrenonceBatchError::UnsupportedVersion)
        );
        let mut trailing = serialized.clone();
        trailing.push(0x00);
        assert_eq!(
            Musig2PrenonceBatch::deserialize(&trailing),
            Err(Musig2PrenonceBatchError::InvalidLength)
        );
        assert_eq!(
            Musig2PrenonceBatch::deserialize(&serialized[..serialized.len() - 1]),
            Err(Musig2PrenonceBatchError::InvalidLength)
        );
    }

    #[test]
    fn musig2_prenonce_batch_from_response() {
        let batch = prenonce_batch();
        let mut response = batch.participant_pubkey.to_vec();
        response.extend(batch.aggregate_pubkey);
        response.extend(hex!("00000007"));
        let yielded: Vec<Vec<u8>> = batch
            .pubnonces
            .iter()
            .map(|(i, pubnonce)| [&i.to_be_bytes()[..], &pubnonce[..]].concat())
            .collect();

        assert_eq!(
            Musig2PrenonceBatch::from_response(0x01020304, 5, &response, &yielded),
            Ok(batch)
        );
        assert_eq!(
            Musig2PrenonceBatch::from_response(0x01020304, 5, &response[..69], &yielded),
            Err(Musig2PrenonceBatchError::InvalidLength)
        );
        assert_eq!(
            Musig2PrenonceBatch::from_response(0x01020304, 5, &response, &[vec![0x00; 71]]),
            Err(Musig2PrenonceBatchError::InvalidLength)
        );
    }
}
