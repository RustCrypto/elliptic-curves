#![cfg(feature = "dsa")]

use elliptic_curve::ops::Reduce;
use proptest::prelude::*;
use sm2::{
    NonZeroScalar, Scalar, U256,
    dsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    },
};

const IDENTITY: &str = "test@rustcrypto.org";

/// Helper function to create a signing key from test data
fn create_test_signing_key() -> SigningKey {
    // Use a fixed test key for deterministic testing
    let test_key = [42u8; 32];
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&test_key.into());
    let scalar = NonZeroScalar::new(scalar).unwrap();
    SigningKey::from_nonzero_scalar(IDENTITY, scalar).unwrap()
}

#[test]
fn test_varying_message_lengths() {
    let sk = create_test_signing_key();
    let test_messages = vec![
        vec![],          // Empty message
        vec![1u8; 1],    // 1 byte
        vec![2u8; 32],   // 32 bytes
        vec![3u8; 1024], // 1KB
    ];

    for msg in test_messages {
        let sig = sk.sign(&msg);
        assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
    }
}

#[test]
fn test_signature_tampering() {
    let sk = create_test_signing_key();
    let msg = b"test message";
    let sig = sk.sign(msg);
    let mut tampered_sig = sig.to_bytes();

    // Modify each byte of signature
    for i in 0..64 {
        tampered_sig[i] ^= 1;
        let invalid_sig = Signature::from_bytes(&tampered_sig).unwrap();
        assert!(sk.verifying_key().verify(msg, &invalid_sig).is_err());
        tampered_sig[i] ^= 1; // Restore
    }
}

#[test]
fn test_special_messages() {
    let sk = create_test_signing_key();
    let special_msgs = vec![
        vec![0u8; 32],      // All zeros
        vec![255u8; 32],    // All ones
        b"\n\r\t".to_vec(), // Control chars
    ];

    for msg in special_msgs {
        let sig = sk.sign(&msg);
        assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
    }
}

proptest! {
    #[test]
    fn test_signature_consistency(
        msg1 in any::<Vec<u8>>(),
        msg2 in any::<Vec<u8>>()
    ) {
        let sk = create_test_signing_key();
        let sig1 = sk.sign(&msg1);
        let sig2 = sk.sign(&msg1); // Same message
        let sig3 = sk.sign(&msg2); // Different message

        // Same message should verify with both signatures
        prop_assert!(sk.verifying_key().verify(&msg1, &sig1).is_ok());
        prop_assert!(sk.verifying_key().verify(&msg1, &sig2).is_ok());

        // Different messages should have different signatures
        if msg1 != msg2 {
            prop_assert_ne!(sig1.to_bytes(), sig3.to_bytes());
        }
    }
}
