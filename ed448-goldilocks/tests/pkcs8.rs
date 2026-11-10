//! PKCS#8 / SPKI decoding tests for Ed448 keys (RFC 8410).
#![cfg(all(feature = "signing", feature = "pkcs8"))]

use ed448_goldilocks::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed448_goldilocks::{SigningKey, VerifyingKey};

/// Key from RustCrypto/elliptic-curves#1326, generated with OpenSSL.
const ISSUE_1326_DER: &[u8] = include_bytes!("data/ed448_1326.der");
/// CURDLE test vectors from RustCrypto/signatures (`ed448/tests/examples`).
const CURDLE_PKCS8_DER: &[u8] = include_bytes!("data/curdle_pkcs8_v1.der");
const CURDLE_PUBKEY_DER: &[u8] = include_bytes!("data/curdle_pubkey.der");

const KEY_LEN: usize = 57;

/// The PKCS#8 vectors carry no public key, and the SPKI vector ends with the
/// raw public key, so the raw key is the trailing 57 bytes of each DER file.
fn tail(der: &[u8]) -> &[u8] {
    &der[der.len() - KEY_LEN..]
}

#[test]
fn decode_issue_1326_key() {
    let key = SigningKey::from_pkcs8_der(ISSUE_1326_DER).expect("valid RFC 8410 key");
    assert_eq!(key.as_bytes().as_slice(), tail(ISSUE_1326_DER));
}

#[test]
fn decode_curdle_vectors() {
    let key = SigningKey::from_pkcs8_der(CURDLE_PKCS8_DER).expect("valid RFC 8410 key");
    assert_eq!(key.as_bytes().as_slice(), tail(CURDLE_PKCS8_DER));

    let public = VerifyingKey::from_public_key_der(CURDLE_PUBKEY_DER).expect("valid SPKI");
    assert_eq!(&public.to_bytes()[..], tail(CURDLE_PUBKEY_DER));
    assert_eq!(key.verifying_key(), public);
}

#[cfg(feature = "alloc")]
#[test]
fn pkcs8_der_roundtrip() {
    use ed448_goldilocks::pkcs8::EncodePrivateKey;

    let key = SigningKey::from_pkcs8_der(CURDLE_PKCS8_DER).expect("valid RFC 8410 key");
    let der = key.to_pkcs8_der().expect("encodes");
    let decoded = SigningKey::from_pkcs8_der(der.as_bytes()).expect("decodes");
    assert_eq!(key, decoded);
}
