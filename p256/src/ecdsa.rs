//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::NistP256;

#[cfg(feature = "arithmetic")]
use {
    crate::{AffinePoint, ProjectivePoint, Scalar, ScalarBytes},
    ecdsa::{
        hazmat::{SignPrimitive, VerifyPrimitive},
        Error,
    },
    elliptic_curve::{ops::Invert, subtle::CtOption},
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
    #[allow(clippy::many_single_char_names)]
    fn try_sign_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &ScalarBytes,
    ) -> Result<Signature, Error>
    where
        K: AsRef<Scalar> + Invert<Output = Scalar>,
    {
        let k_inverse = ephemeral_scalar.invert();
        let k = ephemeral_scalar.as_ref();

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

    #[cfg(feature = "rand")]
    use {crate::BlindedScalar, elliptic_curve::rand_core::OsRng};

    ecdsa::new_signing_test!(ECDSA_TEST_VECTORS);
    ecdsa::new_verification_test!(ECDSA_TEST_VECTORS);

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
