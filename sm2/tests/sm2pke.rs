#![cfg(feature = "pke")]

use elliptic_curve::{NonZeroScalar, ops::Reduce};
use hex_literal::hex;
use proptest::prelude::*;

use rand_core::OsRng;
#[cfg(feature = "alloc")]
use sm2::pke::Mode;
use sm2::{
    Scalar, SecretKey, Sm2, U256,
    pke::{Cipher, EcDecrypt, EcEncrypt},
};

// private key bytes
const PRIVATE_KEY: [u8; 32] =
    hex!("3DDD2A3679BF6F1DFC3B49D3E99114718E48EC170EB4E4D3A82052DAB19E8B50");
const MSG: &[u8] = b"plaintext";

// starts with 04, ciphertext
const CIPHER: [u8; 106] = hex!(
    "041ed68db303f5bc6bce516d5a62e1cd16781d3007df6864d970a56d46a6cecca0e0d33bfc71e78c440ae6afeef1a18cce473b3e27002189a058ddadc9182c80a3f13be66476ba6ef66d95a7fb11f30de441b3b66d566e48348bd830e584e7ec37f9b704ef32eba9055c"
);
// TODO: [`Cipher`]  ASN1 Encode and Decode
// asn.1: openssl pkeyutl -encrypt -pubin -in plaintext -inkey sm2.pub -out cipher
// const ASN1_CIPHER: [u8; 116] = hex!(
//     "307202206ba17ad462a75beeb2caf8a1282687ab7e2f248b776a481612d89425a519ce6002210083e1de8c57dae995137227839d3880eaf9fe82a885a750be29ebe58193c8e31a0420d513a555087c2b17a88dd62749435133d325a4afca675284c85d754ba35670f80409bd3a294a6d50184b37"
// );

#[test]
fn decrypt_verify() {
    let public_key: SecretKey = NonZeroScalar::<Sm2>::try_from(PRIVATE_KEY.as_ref() as &[u8])
        .unwrap()
        .into();
    let cipher = Cipher::from_slice(&CIPHER, sm2::pke::Mode::C1C3C2).unwrap();
    let mut out = vec![0; cipher.c2().len()];
    public_key.decrypt_into(&cipher, &mut out).unwrap();
    assert_eq!(out, MSG);
}

// TODO: [`Cipher`]  ASN1 Encode and Decode
// #[test]
// fn decrypt_der_verify() {
//     let dk = DecryptingKey::new_with_mode(
//         NonZeroScalar::<Sm2>::try_from(PRIVATE_KEY.as_ref() as &[u8]).unwrap(),
//         sm2::pke::Mode::C1C2C3,
//     );
//     assert_eq!(dk.decrypt_der(&ASN1_CIPHER).unwrap(), MSG);
// }

prop_compose! {
    fn secret_key()(bytes in any::<[u8; 32]>()) -> SecretKey {
        loop {
            let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into());
            if let Some(scalar) = Option::<NonZeroScalar::<Sm2>>::from(NonZeroScalar::<Sm2>::new(scalar)) {

                return SecretKey::new(scalar.into());
            }
        }
    }
}

proptest! {

    #[test]
    #[cfg(feature="alloc")]
    fn encrypt_and_decrpyt(key in secret_key()) {
        let cipher = key.encrypt( MSG).unwrap();
        let cipher_bytes = cipher.to_vec(Mode::C1C3C2);
        let cipher = Cipher::from_slice(&cipher_bytes, Mode::C1C3C2).unwrap();
        let text = key.decrypt(&cipher).unwrap();
        assert_eq!(text, MSG);

        let cipher = key.encrypt(MSG).unwrap();
        let cipher_bytes = cipher.to_vec(Mode::C1C2C3);
        let cipher = Cipher::from_slice(&cipher_bytes, Mode::C1C2C3).unwrap();
        let text = key.decrypt(&cipher).unwrap();
        assert_eq!(text, MSG);

    }

    #[test]
    fn encrypt_and_decrpyt_no_std(key in secret_key()) {
        let mut out = vec![0; MSG.len()];
        let cipher = key.encrypt_buf_rng(&mut OsRng, MSG, &mut out).unwrap();
        let mut deout = vec![0; MSG.len()];
        key.decrypt_into(&cipher, &mut deout).unwrap();
        assert_eq!(deout, MSG);

    }


}
