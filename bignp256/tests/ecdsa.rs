//! bignp256 ECDSA Tests

#![cfg(feature = "ecdsa")]

// Test vectors from https://apmi.bsu.by/assets/files/std/met-v10.zip
// file met-10145-10-01.pdf, section 6.2

use elliptic_curve::ops::Reduce;
use hex_literal::hex;
use proptest::prelude::*;

use bignp256::{
    FieldBytes, NonZeroScalar, Scalar,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
};

const PRIVATE_KEY: [u8; 32] =
    hex!("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269");

const PUBLIC_KEY: [u8; 64] = hex!(
    "BD1A5650 179D79E0 3FCEE49D 4C2BD5DD F54CE46D 0CF11E4F F87BF7A8 90857FD0"
    "7AC6A603 61E8C817 3491686D 461B2826 190C2EDA 5909054A 9AB84D2A B9D99A90"
);

const MSG: [u8; 13] = hex!("B194BAC8 0A08F53B 366D008E 58");

const SIG: [u8; 48] = hex!(
    "19D32B7E 01E25BAE 4A70EB6B CA42602C"
    "CA6A1394 4451BCC5 D4C54CFD 8737619C 328B8A58 FB9C68FD 17D569F7 D06495FB"
);

#[test]
fn verify_test_vector() {
    let sk = SigningKey::from_slice(&PRIVATE_KEY).unwrap();
    let vk = VerifyingKey::from_bytes(&PUBLIC_KEY).unwrap();

    assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());

    let sig = Signature::try_from(&SIG).unwrap();

    assert!(vk.verify(MSG.as_slice(), &sig).is_ok());
}

prop_compose! {
    fn signing_key()(bytes in any::<[u8; 32]>()) -> SigningKey {
        loop {
            let scalar = <Scalar as Reduce<FieldBytes>>::reduce(&bytes.into());
            if let Some(scalar) = Option::from(NonZeroScalar::new(scalar)) {
                return SigningKey::from_nonzero_scalar(scalar);
            }
        }
    }
}

proptest! {
    #[test]
    fn sign_and_verify(sk in signing_key()) {
        let signature = sk.sign(&MSG);
        prop_assert!(sk.verifying_key().verify(&MSG, &signature).is_ok());
    }

    #[test]
    fn reject_invalid_signature(sk in signing_key(), byte in 0usize..32, bit in 0usize..8) {
        let mut signature_bytes = sk.sign(&MSG).to_bytes();

        // tweak signature to make it invalid
        signature_bytes[byte] ^= 1 << bit;

        let signature = Signature::from_bytes(&signature_bytes).unwrap();
        prop_assert!(sk.verifying_key().verify(&MSG, &signature).is_err());
    }
}
