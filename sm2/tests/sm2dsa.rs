//! ECDSA tests.

#![cfg(feature = "dsa")]

use elliptic_curve::ops::Reduce;
use hex_literal::hex;
use proptest::prelude::*;
use sm2::{
    FieldBytes, NonZeroScalar, Scalar,
    dsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
};

const PUBLIC_KEY: [u8; 65] = hex!(
    "0408D77AE04C01CC4C1104360DD8AF6B6F7DF334283D7C1A6AFD5652407B87BEE5014E2A57C36C150D16324DC664E31E6432359609C4E79847A5B161C8C7364C8A"
);
const IDENTITY: &str = "example@rustcrypto.org";
const MSG: &[u8] = b"testing";

// Created using:
// $ openssl pkeyutl -sign -in - -inkey pkcs8-private-key.pem -out sig -digest sm3 -pkeyopt distid:example@rustcrypto.org
const SIG: [u8; 64] = hex!(
    "d1dcccedd9fb785e0f67c16b7c52901625c0b69de9bca2144acc7be713cad2fc" // r
    "f7d1eae6e3a157b36c65f672f738ca8b46298bf149a6510072c431b49cd88b1c" // s
);

#[test]
fn verify_test_vector() {
    let vk = VerifyingKey::from_sec1_bytes(IDENTITY, &PUBLIC_KEY).unwrap();
    let sig = Signature::from_bytes(&SIG.into()).expect("decoded Signature failed");
    assert!(vk.verify(MSG, &sig).is_ok());
}

const SIG_DER: [u8; 71] = hex!(
    "304502201d09df0f021b8c9aa7a437c713f11f9bc5ef49b5f053de912d6a3a8b68d49688022100c8acda282cb69bd4734b9c164925772f8f5cb23b273c222d69a4a49bb40a8701"
);

#[test]
#[cfg(feature = "der")]
fn test_signature_encoding() {
    let sig = Signature::from_der(&SIG_DER).expect("decoded Signature failed");
    assert_eq!(sig.r().to_bytes().to_vec(), SIG_DER[4..36].to_vec());
    assert_eq!(sig.s().to_bytes().to_vec(), SIG_DER[39..71].to_vec());
}

prop_compose! {
    fn signing_key()(bytes in any::<[u8; 32]>()) -> SigningKey {
        loop {
            let scalar = <Scalar as Reduce<FieldBytes>>::reduce(&bytes.into());
            if let Some(scalar) = Option::from(NonZeroScalar::new(scalar)) {
                return SigningKey::from_nonzero_scalar(IDENTITY, scalar).unwrap();
            }
        }
    }
}

proptest! {
    #[test]
    fn sign_and_verify(sk in signing_key()) {
        let signature = sk.sign(MSG);
        prop_assert!(sk.verifying_key().verify(MSG, &signature).is_ok());
    }

    #[test]
    #[cfg(feature = "der")]
    fn sign_and_verify_der(sk in signing_key()) {
        let signature = sk.sign(MSG);
        let signature_der = signature.to_der();
        let signature_der_bytes = signature_der.to_vec();
        let signature = Signature::from_der(&signature_der_bytes).expect("decoded Signature failed");
        prop_assert!(sk.verifying_key().verify(MSG, &signature).is_ok());
    }

    #[test]
    fn reject_invalid_signature(sk in signing_key(), byte in 0usize..32, bit in 0usize..8) {
        let mut signature_bytes = sk.sign(MSG).to_bytes();

        // tweak signature to make it invalid
        signature_bytes[byte] ^= 1 << bit;

        let signature = Signature::from_bytes(&signature_bytes).unwrap();
        prop_assert!(sk.verifying_key().verify(MSG, &signature).is_err());
    }
}
