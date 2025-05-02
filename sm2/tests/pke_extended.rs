#![cfg(feature = "pke")]

use elliptic_curve::ops::Reduce;
use proptest::prelude::*;
use sm2::{
    NonZeroScalar, Scalar, U256,
    pke::{DecryptingKey, EncryptingKey, Mode},
};

/// Helper function to create a decrypting key from test data
fn create_test_key() -> DecryptingKey {
    // Use a fixed test key for deterministic testing
    let test_key = [42u8; 32];
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&test_key.into());
    let scalar = NonZeroScalar::new(scalar).unwrap();
    DecryptingKey::from_nonzero_scalar(scalar).unwrap()
}

#[test]
fn test_varying_plaintext_lengths() {
    let dk = create_test_key();
    let ek = dk.encrypting_key();
    let test_plaintexts = vec![
        vec![],         // Empty message
        vec![1u8; 1],   // 1 byte
        vec![2u8; 32],  // 32 bytes
        vec![3u8; 256], // 256 bytes
    ];

    for plaintext in test_plaintexts {
        let ciphertext = ek.encrypt(&mut rand_core::OsRng, &plaintext).unwrap();
        let decrypted = dk.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_ciphertext_tampering() {
    let dk = create_test_key();
    let ek = dk.encrypting_key();
    let plaintext = b"test message";
    let ciphertext = ek.encrypt(&mut rand_core::OsRng, plaintext).unwrap();

    // Test tampering with each byte
    for i in 0..ciphertext.len() {
        let mut tampered = ciphertext.clone();
        tampered[i] ^= 1;
        assert!(dk.decrypt(&tampered).is_err());
    }
}

#[test]
fn test_special_plaintexts() {
    let dk = create_test_key();
    let ek = dk.encrypting_key();
    let special_plaintexts = vec![
        vec![0u8; 32],                // All zeros
        vec![255u8; 32],              // All ones
        b"\n\r\t".to_vec(),           // Control chars
        vec![0xF0, 0x9F, 0x98, 0x81], // UTF-8 emoji
    ];

    for plaintext in special_plaintexts {
        let ciphertext = ek.encrypt(&mut rand_core::OsRng, &plaintext).unwrap();
        let decrypted = dk.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_encryption_modes() {
    let plaintext = b"test message";

    // Test C1C3C2 mode (default)
    let dk_default = create_test_key();
    let ek_default = dk_default.encrypting_key();
    let cipher_default = ek_default
        .encrypt(&mut rand_core::OsRng, plaintext)
        .unwrap();
    assert_eq!(plaintext[..], dk_default.decrypt(&cipher_default).unwrap());

    // Test C1C2C3 mode
    let dk_c1c2c3 =
        DecryptingKey::new_with_mode(NonZeroScalar::new(Scalar::ONE).unwrap(), Mode::C1C2C3);
    let ek_c1c2c3 = dk_c1c2c3.encrypting_key();
    let cipher_c1c2c3 = ek_c1c2c3.encrypt(&mut rand_core::OsRng, plaintext).unwrap();
    assert_eq!(plaintext[..], dk_c1c2c3.decrypt(&cipher_c1c2c3).unwrap());

    // Verify that different modes produce different ciphertexts
    assert_ne!(cipher_default, cipher_c1c2c3);
}

proptest! {
    #[test]
    fn test_encryption_consistency(
        plaintext1 in any::<Vec<u8>>(),
        plaintext2 in any::<Vec<u8>>()
    ) {
        let dk = create_test_key();
        let ek = dk.encrypting_key();

        // Same plaintext should decrypt correctly with different randomness
        let cipher1 = ek.encrypt(&mut rand_core::OsRng, &plaintext1).unwrap();
        let cipher2 = ek.encrypt(&mut rand_core::OsRng, &plaintext1).unwrap();

        // Different ciphertexts for same plaintext (due to randomness)
        prop_assert_ne!(cipher1, cipher2);

        // Both should decrypt to original plaintext
        prop_assert_eq!(dk.decrypt(&cipher1).unwrap(), plaintext1);
        prop_assert_eq!(dk.decrypt(&cipher2).unwrap(), plaintext1);

        // Different plaintexts should produce different ciphertexts
        if plaintext1 != plaintext2 {
            let cipher3 = ek.encrypt(&mut rand_core::OsRng, &plaintext2).unwrap();
            prop_assert_ne!(dk.decrypt(&cipher1).unwrap(), dk.decrypt(&cipher3).unwrap());
        }
    }
} 