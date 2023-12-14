//! bign256 DSA Tests

#![cfg(feature = "dsa")]

use bign256::{
    dsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    NonZeroScalar, Scalar, U256,
};
use elliptic_curve::ops::Reduce;
use hex_literal::hex;
use proptest::prelude::*;

const PUBLIC_KEY: [u8; 65] = hex!(
    "04
    D07F8590A8F77BF84F1EF10C6DE44CF5DDD52B4C9DE4CE3FE0799D1750561ABD
    909AD9B92A4DB89A4A050959DA2E0C1926281B466D68913417C8E86103A6C67A"
);
const MSG: &[u8] = b"testing";
const SIG: [u8; 48] = hex!(
    "63F59C523FF1780851143114FFBC5C13"
    "9BE81FF88F9D7F7FE209A6914198044C2A41D37B8439AAB42983FDB04AC2C326"
);

#[test]
fn verify_test_vector() {
    let vk = VerifyingKey::from_sec1_bytes(&PUBLIC_KEY).unwrap();
    let sig = Signature::try_from(&SIG).unwrap();
    assert!(vk.verify(MSG, &sig).is_ok());
}

prop_compose! {
    fn signing_key()(bytes in any::<[u8; 32]>()) -> SigningKey {
        loop {
            let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into());
            if let Some(scalar) = Option::from(NonZeroScalar::new(scalar)) {
                return SigningKey::from_nonzero_scalar(scalar).unwrap();
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
