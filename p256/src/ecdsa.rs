//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::NistP256;

#[cfg(feature = "arithmetic")]
use {
    crate::{AffinePoint, ProjectivePoint, Scalar, ScalarBytes},
    ecdsa::{
        hazmat::{SignPrimitive, VerifyPrimitive},
        Error,
    },
    elliptic_curve::subtle::CtOption,
};

/// ECDSA/P-256 signature (fixed-size)
pub type Signature = ::ecdsa::Signature<NistP256>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa::hazmat::DigestPrimitive for NistP256 {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "arithmetic")]
impl SignPrimitive<NistP256> for Scalar {
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

        // prevent side channel analysis of scalar inversion by pre-and-post-multiplying
        // with the random masking scalar
        let k_inverse = match masking_scalar.as_ref() {
            Some(s) => (k * s).invert_vartime().unwrap() * s,
            None => k.invert().unwrap(),
        };

        // Compute `x`-coordinate of affine point 𝑘×𝑮
        let x = (ProjectivePoint::generator() * k).to_affine().unwrap().x;

        // Lift `x` (element of base field) to serialized big endian integer,
        // then reduce it to an element of the scalar field
        let r = Scalar::from_bytes_reduced(&x.to_bytes());

        // Reduce message hash to an element of the scalar field
        let z = Scalar::from_bytes_reduced(hashed_msg.as_ref());

        // Compute `s` as a signature over `r` and `z`
        let s = k_inverse * &(z + &(r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        Ok(Signature::from_scalars(&r.into(), &s.into()))
    }
}

#[cfg(feature = "arithmetic")]
impl VerifyPrimitive<NistP256> for AffinePoint {
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

#[cfg(all(test, feature = "arithmetic"))]
mod tests {
    use super::*;
    use crate::test_vectors::ecdsa::ECDSA_TEST_VECTORS;

    ecdsa::new_signing_test!(ECDSA_TEST_VECTORS);
    ecdsa::new_verification_test!(ECDSA_TEST_VECTORS);
}
