//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub mod recoverable;

use super::Secp256k1;

#[cfg(feature = "arithmetic")]
use {
    crate::{AffinePoint, ProjectivePoint, Scalar, ScalarBytes},
    ecdsa::{
        hazmat::{SignPrimitive, VerifyPrimitive},
        Error,
    },
    elliptic_curve::subtle::{ConditionallySelectable, CtOption},
};

/// ECDSA/secp256k1 signature (fixed-size)
pub type Signature = ::ecdsa::Signature<Secp256k1>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa::hazmat::DigestPrimitive for Secp256k1 {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "arithmetic")]
impl SignPrimitive<Secp256k1> for Scalar {
    type Scalar = Scalar;

    #[allow(clippy::many_single_char_names)]
    fn try_sign_prehashed(
        &self,
        ephemeral_scalar: &Scalar,
        masking_scalar: Option<&Scalar>,
        hashed_msg: &ScalarBytes,
    ) -> Result<Signature, Error> {
        let k = ephemeral_scalar;

        if k.is_zero().into() {
            return Err(Error::new());
        }

        // TODO(tarcieri): masking_scalar
        assert!(masking_scalar.is_none(), "todo: masking_scalar support");

        // Compute `x`-coordinate of affine point 𝑘×𝑮
        let x = (ProjectivePoint::generator() * k).to_affine().unwrap().x;

        // Lift `x` (element of base field) to serialized big endian integer,
        // then reduce it to an element of the scalar field
        let r = Scalar::from_bytes_reduced(&x.to_bytes());

        // Reduce message hash to an element of the scalar field
        let z = Scalar::from_bytes_reduced(hashed_msg.as_ref());

        // Compute `s` as a signature over `r` and `z`
        let s = k.invert().unwrap() * &(z + &(r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        let signature = Signature::from_scalars(&r.into(), &s.into());
        normalize_s(&signature)
    }
}

#[cfg(feature = "arithmetic")]
impl VerifyPrimitive<Secp256k1> for AffinePoint {
    fn verify_prehashed(
        &self,
        hashed_msg: &ScalarBytes,
        signature: &Signature,
    ) -> Result<(), Error> {
        let maybe_r =
            Scalar::from_bytes(signature.r().as_ref()).and_then(|r| CtOption::new(r, !r.is_zero()));

        let maybe_s =
            Scalar::from_bytes(signature.s().as_ref()).and_then(|s| CtOption::new(s, !s.is_zero()));

        // TODO(tarcieri): replace with into conversion when available (see subtle#73)
        let (r, s) = if maybe_r.is_some().into() && maybe_s.is_some().into() {
            (maybe_r.unwrap(), maybe_s.unwrap())
        } else {
            return Err(Error::new());
        };

        let z = Scalar::from_bytes_reduced(hashed_msg.as_ref());
        let s_inv = s.invert().unwrap();
        let u1 = z * &s_inv;
        let u2 = r * &s_inv;

        let x = ((&ProjectivePoint::generator() * &u1) + &(ProjectivePoint::from(*self) * &u2))
            .to_affine()
            .unwrap()
            .x;

        if Scalar::from_bytes_reduced(&x.to_bytes()) == r {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
/// Normalize signature into "low S" form as described in
/// [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub fn normalize_s(signature: &Signature) -> Result<Signature, Error> {
    use core::convert::TryInto;
    let s_option = Scalar::from_bytes(signature.as_ref()[32..].try_into().unwrap());

    // Not constant time, but we're operating on public values
    let s = if s_option.is_some().into() {
        s_option.unwrap()
    } else {
        return Err(Error::new());
    };

    // Negate `s` if it's within the upper half of the modulus
    let s_neg = -s;
    let low_s = Scalar::conditional_select(&s, &s_neg, s.is_high());

    Ok(Signature::from_scalars(
        signature.r(),
        &low_s.to_bytes().into(),
    ))
}

#[cfg(all(test, feature = "arithmetic"))]
mod tests {
    use super::*;
    use crate::test_vectors::ecdsa::ECDSA_TEST_VECTORS;
    use ecdsa::signature::Signature as _;

    ecdsa::new_signing_test!(ECDSA_TEST_VECTORS);
    ecdsa::new_verification_test!(ECDSA_TEST_VECTORS);

    // Test vectors generated using rust-secp256k1
    #[test]
    #[rustfmt::skip]
    fn normalize_s_high() {
        let sig_hi = Signature::from_bytes(&[
            0x20, 0xc0, 0x1a, 0x91, 0x0e, 0xbb, 0x26, 0x10,
            0xaf, 0x2d, 0x76, 0x3f, 0xa0, 0x9b, 0x3b, 0x30,
            0x92, 0x3c, 0x8e, 0x40, 0x8b, 0x11, 0xdf, 0x2c,
            0x61, 0xad, 0x76, 0xd9, 0x70, 0xa2, 0xf1, 0xbc,
            0xee, 0x2f, 0x11, 0xef, 0x8c, 0xb0, 0x0a, 0x49,
            0x61, 0x7d, 0x13, 0x57, 0xf4, 0xd5, 0x56, 0x41,
            0x09, 0x0a, 0x48, 0xf2, 0x01, 0xe9, 0xb9, 0x59,
            0xc4, 0x8f, 0x6f, 0x6b, 0xec, 0x6f, 0x93, 0x8f,
        ]).unwrap();

        let sig_lo = Signature::from_bytes(&[
            0x20, 0xc0, 0x1a, 0x91, 0x0e, 0xbb, 0x26, 0x10,
            0xaf, 0x2d, 0x76, 0x3f, 0xa0, 0x9b, 0x3b, 0x30,
            0x92, 0x3c, 0x8e, 0x40, 0x8b, 0x11, 0xdf, 0x2c,
            0x61, 0xad, 0x76, 0xd9, 0x70, 0xa2, 0xf1, 0xbc,
            0x11, 0xd0, 0xee, 0x10, 0x73, 0x4f, 0xf5, 0xb6,
            0x9e, 0x82, 0xec, 0xa8, 0x0b, 0x2a, 0xa9, 0xbd,
            0xb1, 0xa4, 0x93, 0xf4, 0xad, 0x5e, 0xe6, 0xe1,
            0xfb, 0x42, 0xef, 0x20, 0xe3, 0xc6, 0xad, 0xb2,
        ]).unwrap();

        let sig_normalized = normalize_s(&sig_hi).unwrap();
        assert_eq!(sig_lo, sig_normalized);
    }

    #[test]
    fn normalize_s_low() {
        #[rustfmt::skip]
        let sig = Signature::from_bytes(&[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]).unwrap();

        let sig_normalized = normalize_s(&sig).unwrap();
        assert_eq!(sig, sig_normalized);
    }
}
