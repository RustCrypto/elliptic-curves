//! bign256 DSA Tests

#![cfg(feature = "ecdsa")]

use elliptic_curve::ops::Reduce;
use hex_literal::hex;
use proptest::prelude::*;

use bign256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    NonZeroScalar, Scalar, U256,
};

const PUBLIC_KEY: [u8; 64] = hex!(
    "BD1A5650 179D79E0 3FCEE49D 4C2BD5DD F54CE46D 0CF11E4F F87BF7A8 90857FD0"
    "7AC6A603 61E8C817 3491686D 461B2826 190C2EDA 5909054A 9AB84D2A B9D99A90"
);

const MSG: &[u8] = b"testing";
const SIG: [u8; 48] = hex!(
    "63F59C523FF1780851143114FFBC5C13"
    "9BE81FF88F9D7F7FE209A6914198044C2A41D37B8439AAB42983FDB04AC2C326"
);

#[test]
fn verify_test_vector() {
    let vk = VerifyingKey::from_bytes(&PUBLIC_KEY).unwrap();
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
