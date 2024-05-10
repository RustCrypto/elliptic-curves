#![cfg(feature = "pkcs8")]

use hex_literal::hex;
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

use bign256::{PublicKey, SecretKey};

const PKCS8_PRIVATE_KEY_DER: &[u8; 65] = include_bytes!("examples/pkcs8-private.der");
#[cfg(feature = "pem")]
const PKCS8_PRIVATE_KEY_PEM: &str = include_str!("examples/pkcs8-private.pem");
const PKCS8_PUBLIC_KEY_DER: &[u8; 95] = include_bytes!("examples/pkcs8-public.der");
#[cfg(feature = "pem")]
const PKCS8_PUBLIC_KEY_PEM: &str = include_str!("examples/pkcs8-public.pem");

#[test]
fn decode_pkcs8_private_key_from_der() {
    let secret_key = SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    let expected_scalar = hex!("1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269");
    assert_eq!(secret_key.to_bytes().as_slice(), &expected_scalar[..]);
}

#[test]
fn decode_pkcs8_public_key_from_der() {
    let public_key = PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    let expected_point = hex!("\
    B2 D8 99 74 6C EB 2D 38 90 1C EF 42 46 39 EA 30 FD A2 72 0B E7 C1 BA 3F 04 BC 31 5D F2 41 2B A9 \
    38 0E A8 EC E0 F7 A7 BA 7E A9 65 2D BA C5 3B 82 7B D2 C2 FB 59 84 86 98 DE 2E A6 75 96 05 EB 96\
    ");
    assert_eq!(public_key.to_bytes().as_ref(), &expected_point[..]);
}

#[test]
#[cfg(feature = "pem")]
fn decode_pkcs8_private_key_from_pem() {
    let secret_key = PKCS8_PRIVATE_KEY_PEM.parse::<SecretKey>().unwrap();

    // Ensure key parses equivalently to DER
    let der_key = SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    assert_eq!(secret_key.to_bytes(), der_key.to_bytes());
}

#[test]
#[cfg(feature = "pem")]
fn decode_pkcs8_public_key_from_pem() {
    let public_key = PKCS8_PUBLIC_KEY_PEM.parse::<PublicKey>().unwrap();

    // Ensure key parses equivalently to DER
    let der_key = PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    assert_eq!(public_key, der_key);
}

#[test]
#[cfg(feature = "pem")]
fn encode_pkcs8_private_key_to_der() {
    let original_secret_key = SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    let reencoded_secret_key = original_secret_key.to_pkcs8_der();
    assert_eq!(
        reencoded_secret_key.unwrap().to_bytes().to_vec(),
        &PKCS8_PRIVATE_KEY_DER[..]
    );
}

#[test]
#[cfg(feature = "pem")]
fn encode_pkcs8_public_key_to_der() {
    let original_public_key = PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    let reencoded_public_key = original_public_key.to_public_key_der().unwrap();
    assert_eq!(reencoded_public_key.as_ref(), &PKCS8_PUBLIC_KEY_DER[..]);
}

#[test]
#[cfg(feature = "pem")]
fn encode_pkcs8_private_key_to_pem() {
    let original_secret_key = SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    let reencoded_secret_key = original_secret_key
        .to_pkcs8_pem(Default::default())
        .unwrap();
    assert_eq!(reencoded_secret_key.as_str(), PKCS8_PRIVATE_KEY_PEM);
}

#[test]
#[cfg(feature = "pem")]
fn encode_pkcs8_public_key_to_pem() {
    let original_public_key = PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    let reencoded_public_key = original_public_key.to_string();
    assert_eq!(reencoded_public_key.as_str(), PKCS8_PUBLIC_KEY_PEM);
}
