#![cfg(feature = "arithmetic")]

// use ecdsa::{Asn1Signature, FixedSignature};
// use signature::{self, Error};

// use crate::{NistP256, arithmetic::Scalar, SecretKey};
use crate::arithmetic::{AffinePoint, Scalar};

// pub struct Signer {
//     /// P256 secret scalar
//     secret_scalar: Scalar,
// }

/// Possible errors when signing
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The ephemeral scalar was zero
    KIsZero,
    /// The message hash was zero
    MIsZero,
    /// The x-coordinate of the ephemeral point was zero mod n
    RIsZero,
    /// The signature was zero
    SIsZero,
}

// impl signature::Signer<FixedSignature<NistP256>> for Scalar {
impl Scalar {
    /// `hazmat` version of signatures: supply entropic ephemeral scalar, and optionally
    /// for speed a masking scalar. Retry until no numbers happen to be zero.
    // fn try_sign(&self, msg: &[u8]) -> Result<FixedSignature<NistP256>, Error> {
    pub fn try_sign_prehashed(
        &self,
        ephemeral_scalar: Scalar,
        // side channel resistance
        masking_scalar: Option<Scalar>,
        hashed_msg: &[u8; 32],
    ) -> Result<[u8; 64], Error> {
        // calculate `k^{-1}`
        let k = ephemeral_scalar;
        if bool::from(k.is_zero()) {
            return Err(Error::KIsZero);
        }

        // prevent side channel analysis of scalar inversion by pre- and post-multiplying
        // with the random masking scalar
        let k_inverse = match masking_scalar.as_ref() {
            Some(s) => (k * s).invert_vartime().unwrap() * s,
            None => k.invert().unwrap(),
        };

        // calculate `r`, ~the ephemeral public key
        use crate::arithmetic::ProjectivePoint;
        let ephemeral_point: AffinePoint = (ProjectivePoint::generator() * &ephemeral_scalar)
            .to_affine()
            .unwrap();

        // Geometrically, x-coordinate is an element of the base field.
        // to_bytes lifts this to a big-endian integer.
        // This integer is then reduced to an element of the scalar field (n < p).
        let x_coordinate: [u8; 32] = ephemeral_point.x.to_bytes();
        let r = Scalar::from_hash(x_coordinate);
        if bool::from(r.is_zero()) {
            return Err(Error::RIsZero);
        }

        // the message as scalar
        let z = Scalar::from_hash(*hashed_msg);

        // calculate `s`, the "core" signature
        let s = k_inverse * &(z + &(r * self));
        if bool::from(s.is_zero()) {
            return Err(Error::SIsZero);
        }

        let mut bag_of_bytes = [0u8; 64];
        bag_of_bytes[..32].copy_from_slice(&r.to_bytes());
        bag_of_bytes[32..].copy_from_slice(&s.to_bytes());

        Ok(bag_of_bytes)
    }

    /// The associated public key `self * generator`.
    pub fn public_key(&self) -> AffinePoint {
        use crate::arithmetic::ProjectivePoint;
        let maybe_public_point = (ProjectivePoint::generator() * self).to_affine();
        maybe_public_point.unwrap()
    }
}

#[test]
fn is_this_the_real_life_is_this_just_fantasy() {
    let seed = [37u8; 32];
    // let hashed_msg = [42u8; 32];
    // msg = b"Give a dog a bone. This old man came rolling home."
    // h = hashlib.sha256(); h.update(msg); h.digest()
    let hashed_msg: [u8; 32] =
        *b"_\xfdH\xdf\x0b\xd7e\x8aei\x1f&\xbbb\x82iE<\x9c\xbe1\x9d\x8c\"\x00U\xd5B\xae\x17r7";
    let ephemeral_scalar = Scalar::from_bytes([79u8; 32]).unwrap();
    let masking_scalar = Scalar::from_bytes([69u8; 32]).unwrap();

    let scalar = Scalar::from_bytes(seed).unwrap();
    let public_point = scalar.public_key();

    let public_bytes = {
        let mut pub_key = [0u8; 64];
        let pre = public_point.to_uncompressed_pubkey();
        pub_key.copy_from_slice(&pre.as_bytes()[1..]);
        pub_key
    };
    println!("public key: {:?}", public_bytes.as_ref());

    let signature = scalar
        .try_sign_prehashed(ephemeral_scalar, Some(masking_scalar), &hashed_msg)
        .unwrap();
    println!("signature: {:?}", signature.as_ref());
}
