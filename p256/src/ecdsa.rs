//! Elliptic Curve Digital Signature Algorithm (ECDSA)

use super::NistP256;
use core::borrow::Borrow;

#[cfg(feature = "ecdsa")]
use {
    crate::{AffinePoint, ElementBytes, ProjectivePoint, Scalar},
    ecdsa_core::{
        hazmat::{SignPrimitive, VerifyPrimitive},
        Error,
    },
    elliptic_curve::{ops::Invert, subtle::CtOption},
};

/// ECDSA/P-256 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<NistP256>;

/// ECDSA/P-256 signer
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type Signer = ecdsa_core::Signer<NistP256>;

/// ECDSA/P-256 verifier
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type Verifier = ecdsa_core::Verifier<NistP256>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa_core::hazmat::DigestPrimitive for NistP256 {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "ecdsa")]
impl SignPrimitive<NistP256> for Scalar {
    #[allow(clippy::many_single_char_names)]
    fn try_sign_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &ElementBytes,
    ) -> Result<Signature, Error>
    where
        K: Borrow<Scalar> + Invert<Output = Scalar>,
    {
        let k_inverse = ephemeral_scalar.invert();
        let k = ephemeral_scalar.borrow();

        if k_inverse.is_none().into() || k.is_zero().into() {
            return Err(Error::new());
        }

        let k_inverse = k_inverse.unwrap();

        // Compute `x`-coordinate of affine point 𝑘×𝑮
        let x = (ProjectivePoint::generator() * k).to_affine().unwrap().x;

        // Lift `x` (element of base field) to serialized big endian integer,
        // then reduce it to an element of the scalar field
        let r = Scalar::from_bytes_reduced(&x.to_bytes());

        // Reduce message hash to an element of the scalar field
        let z = Scalar::from_bytes_reduced(hashed_msg.as_ref());

        // Compute `s` as a signature over `r` and `z`.
        let s = k_inverse * &(z + &(r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        Ok(Signature::from_scalars(&r.into(), &s.into()))
    }
}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<NistP256> for AffinePoint {
    fn verify_prehashed(
        &self,
        hashed_msg: &ElementBytes,
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

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use super::*;
    use crate::test_vectors::ecdsa::ECDSA_TEST_VECTORS;

    #[cfg(feature = "rand")]
    use {crate::BlindedScalar, elliptic_curve::rand_core::OsRng};

    ecdsa_core::new_signing_test!(ECDSA_TEST_VECTORS);
    ecdsa_core::new_verification_test!(ECDSA_TEST_VECTORS);

    #[cfg(feature = "rand")]
    #[test]
    fn scalar_blinding() {
        let vector = &ECDSA_TEST_VECTORS[0];
        let d = Scalar::from_bytes(vector.d.try_into().unwrap()).unwrap();
        let k = Scalar::from_bytes(vector.k.try_into().unwrap()).unwrap();
        let k_blinded = BlindedScalar::new(k, &mut OsRng);
        let sig = d
            .try_sign_prehashed(&k_blinded, GenericArray::from_slice(vector.m))
            .unwrap();

        assert_eq!(vector.r, sig.r().as_slice());
        assert_eq!(vector.s, sig.s().as_slice());
    }
}
