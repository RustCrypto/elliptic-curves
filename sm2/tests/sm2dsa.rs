//! ECDSA tests.

#![cfg(feature = "dsa")]

use elliptic_curve::ops::Reduce;
use hex_literal::hex;
use proptest::prelude::*;
use sm2::{
    dsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    NonZeroScalar, Scalar, U256,
};

const PUBLIC_KEY: [u8; 65] = hex!("0408D77AE04C01CC4C1104360DD8AF6B6F7DF334283D7C1A6AFD5652407B87BEE5014E2A57C36C150D16324DC664E31E6432359609C4E79847A5B161C8C7364C8A");
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
    let sig = Signature::try_from(&SIG).unwrap();
    assert!(vk.verify(MSG, &sig).is_ok());
}

prop_compose! {
    fn signing_key()(bytes in any::<[u8; 32]>()) -> SigningKey {
        loop {
            let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into());
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
    fn reject_invalid_signature(sk in signing_key(), byte in 0usize..32, bit in 0usize..8) {
        let mut signature_bytes = sk.sign(MSG).to_bytes();

        // tweak signature to make it invalid
        signature_bytes[byte] ^= 1 << bit;

        let signature = Signature::from_bytes(&signature_bytes).unwrap();
        prop_assert!(sk.verifying_key().verify(MSG, &signature).is_err());
    }
}
