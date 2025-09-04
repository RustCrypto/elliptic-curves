//! ECDSA tests.

#![cfg(feature = "ecdsa")]

use bp256::r1::ecdsa::{
    SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use proptest::prelude::*;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

prop_compose! {
    fn signing_key()(seed in any::<[u8; 32]>()) -> SigningKey {
        let mut rng = ChaCha8Rng::from_seed(seed);
        SigningKey::try_from_rng(&mut rng).unwrap()
    }
}

proptest! {
    #[test]
    fn recover_from_msg(sk in signing_key()) {
        let msg = b"example";
        let (signature, v) = sk.sign_recoverable(msg).unwrap();
        let recovered_vk = VerifyingKey::recover_from_msg(msg, &signature, v).unwrap();
        prop_assert_eq!(sk.verifying_key(), &recovered_vk);
    }

    #[test]
    fn sign_roundtrip(sk in signing_key()) {
        let msg = b"example";
        let (signature, _v) = sk.try_sign(msg).unwrap();
        let vk = sk.verifying_key();
        prop_assert!(vk.verify(msg, &signature).is_ok());
    }
}
