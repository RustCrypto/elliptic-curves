//! PKCS#8 tests

#![cfg(feature = "pkcs8")]

use hex_literal::hex;
use p256::pkcs8::FromPkcs8;

#[test]
fn parse_pkcs8_private_key() {
    let pkcs8_der = include_bytes!("examples/pkcs8-private-key.der");
    let expected_scalar = hex!("69624171561A63340DE0E7D869F2A05492558E1A04868B6A9F854A866788188D");

    let secret_key = p256::SecretKey::from_pkcs8_der(&pkcs8_der[..]).unwrap();
    assert_eq!(secret_key.to_bytes().as_slice(), &expected_scalar[..]);
}
