//! PKCS#8 tests

#![cfg(feature = "pkcs8")]

use hex_literal::hex;
use p256::pkcs8::FromPkcs8;

/// DER-encoded PKCS#8 private key
const PKCS8_DER: &[u8; 138] = include_bytes!("examples/pkcs8-private-key.der");

/// PEM-encoded PKCS#8 private key
#[cfg(feature = "pem")]
const PKCS8_PEM: &str = include_str!("examples/pkcs8-private-key.pem");

#[test]
fn parse_pkcs8_private_key_from_der() {
    let secret_key = p256::SecretKey::from_pkcs8_der(&PKCS8_DER[..]).unwrap();
    let expected_scalar = hex!("69624171561A63340DE0E7D869F2A05492558E1A04868B6A9F854A866788188D");
    assert_eq!(secret_key.to_bytes().as_slice(), &expected_scalar[..]);
}

#[test]
#[cfg(feature = "pem")]
fn parse_pkcs8_private_key_from_pem() {
    let secret_key = PKCS8_PEM.parse::<p256::SecretKey>().unwrap();

    // Ensure key parses equivalently to DER
    let der_key = p256::SecretKey::from_pkcs8_der(&PKCS8_DER[..]).unwrap();
    assert_eq!(secret_key.to_bytes(), der_key.to_bytes());
}
