//! PKCS#8 tests

#![cfg(feature = "pkcs8")]

use hex_literal::hex;
use sm2::pkcs8::DecodePrivateKey;

#[cfg(feature = "arithmetic")]
use sm2::pkcs8::DecodePublicKey;

#[cfg(all(feature = "arithmetic", feature = "pem"))]
use {
    elliptic_curve::sec1::ToEncodedPoint,
    sm2::elliptic_curve::pkcs8::{EncodePrivateKey, EncodePublicKey},
};

/// DER-encoded PKCS#8 private key
const PKCS8_PRIVATE_KEY_DER: &[u8; 138] = include_bytes!("examples/pkcs8-private-key.der");

/// DER-encoded PKCS#8 public key
#[cfg(feature = "arithmetic")]
const PKCS8_PUBLIC_KEY_DER: &[u8; 91] = include_bytes!("examples/pkcs8-public-key.der");

/// PEM-encoded PKCS#8 private key
#[cfg(feature = "pem")]
const PKCS8_PRIVATE_KEY_PEM: &str = include_str!("examples/pkcs8-private-key.pem");

/// PEM-encoded PKCS#8 public key
#[cfg(all(feature = "arithmetic", feature = "pem"))]
const PKCS8_PUBLIC_KEY_PEM: &str = include_str!("examples/pkcs8-public-key.pem");

/// Extracted via `openssl ec -in pkcs8-private-key.pem -noout -text`
///
/// ```text
/// pub:
///     04:08:d7:7a:e0:4c:01:cc:4c:11:04:36:0d:d8:af:
///     6b:6f:7d:f3:34:28:3d:7c:1a:6a:fd:56:52:40:7b:
///     87:be:e5:01:4e:2a:57:c3:6c:15:0d:16:32:4d:c6:
///     64:e3:1e:64:32:35:96:09:c4:e7:98:47:a5:b1:61:
///     c8:c7:36:4c:8a
/// ```
#[cfg(feature = "arithmetic")]
const SEC1_PUBLIC_KEY: [u8; 65] = hex!("0408D77AE04C01CC4C1104360DD8AF6B6F7DF334283D7C1A6AFD5652407B87BEE5014E2A57C36C150D16324DC664E31E6432359609C4E79847A5B161C8C7364C8A");

#[test]
fn decode_pkcs8_private_key_from_der() {
    let secret_key = sm2::SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    let expected_scalar = hex!("4BB8DF505722299592CBED4283B354A13FF5D3FEEB3A0660C5BDF3C87C559499");
    assert_eq!(secret_key.to_bytes().as_slice(), &expected_scalar[..]);

    #[cfg(feature = "arithmetic")]
    assert_eq!(
        secret_key.public_key().to_encoded_point(false).as_bytes(),
        &SEC1_PUBLIC_KEY[..]
    );
}

#[cfg(feature = "arithmetic")]
#[test]
fn decode_pkcs8_public_key_from_der() {
    let public_key = sm2::PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();

    assert_eq!(
        public_key.to_encoded_point(false).as_bytes(),
        &SEC1_PUBLIC_KEY[..]
    );
}

#[cfg(feature = "pem")]
#[test]
fn decode_pkcs8_private_key_from_pem() {
    let secret_key = PKCS8_PRIVATE_KEY_PEM.parse::<sm2::SecretKey>().unwrap();

    // Ensure key parses equivalently to DER
    let der_key = sm2::SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    assert_eq!(secret_key.to_bytes(), der_key.to_bytes());
}

#[cfg(all(feature = "arithmetic", feature = "pem"))]
#[test]
fn decode_pkcs8_public_key_from_pem() {
    let public_key = PKCS8_PUBLIC_KEY_PEM.parse::<sm2::PublicKey>().unwrap();

    // Ensure key parses equivalently to DER
    let der_key = sm2::PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    assert_eq!(public_key, der_key);
}

#[cfg(all(feature = "arithmetic", feature = "pem"))]
#[test]
fn encode_pkcs8_private_key_to_der() {
    let original_secret_key = sm2::SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    let reencoded_secret_key = original_secret_key.to_pkcs8_der().unwrap();
    assert_eq!(reencoded_secret_key.as_bytes(), &PKCS8_PRIVATE_KEY_DER[..]);
}

#[cfg(all(feature = "arithmetic", feature = "pem"))]
#[test]
fn encode_pkcs8_public_key_to_der() {
    let original_public_key =
        sm2::PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    let reencoded_public_key = original_public_key.to_public_key_der().unwrap();
    assert_eq!(reencoded_public_key.as_ref(), &PKCS8_PUBLIC_KEY_DER[..]);
}

#[cfg(all(feature = "arithmetic", feature = "pem"))]
#[test]
fn encode_pkcs8_private_key_to_pem() {
    let original_secret_key = sm2::SecretKey::from_pkcs8_der(&PKCS8_PRIVATE_KEY_DER[..]).unwrap();
    let reencoded_secret_key = original_secret_key
        .to_pkcs8_pem(Default::default())
        .unwrap();
    assert_eq!(reencoded_secret_key.as_str(), PKCS8_PRIVATE_KEY_PEM);
}

#[cfg(all(feature = "arithmetic", feature = "pem"))]
#[test]
fn encode_pkcs8_public_key_to_pem() {
    let original_public_key =
        sm2::PublicKey::from_public_key_der(&PKCS8_PUBLIC_KEY_DER[..]).unwrap();
    let reencoded_public_key = original_public_key.to_string();
    assert_eq!(reencoded_public_key.as_str(), PKCS8_PUBLIC_KEY_PEM);
}
