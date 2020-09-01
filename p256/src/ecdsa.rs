//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/P-256 signature). Does not require the `arithmetic` feature.
//!   This is useful for 3rd-party crates which wish to use the `Signature`
//!   type for interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait. Example use cases for this include other
//!   software implementations of ECDSA/P-256 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides the [`Signature`], [`Signer`], and [`Verifier`] types
//!   which natively implement ECDSA/P-256 signing and verification.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use p256::{
//!     ecdsa::{Signer, Signature, signature::Signer as _},
//!     elliptic_curve::{Generate},
//!     SecretKey,
//! };
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let secret_key = SecretKey::generate(&mut OsRng);
//! let signer = Signer::new(&secret_key).expect("secret key invalid");
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//!
//! let signature: Signature = signer.sign(message);
//!
//! // Verification
//! use p256::{EncodedPoint, ecdsa::{Verifier, signature::Verifier as _}};
//!
//! let public_key = EncodedPoint::from_secret_key(&secret_key, true).expect("secret key invalid");
//! let verifier = Verifier::new(&public_key).expect("public key invalid");
//!
//! assert!(verifier.verify(message, &signature).is_ok());
//! # }
//! ```

pub use ecdsa_core::signature::{self, Error};

use super::NistP256;

#[cfg(feature = "ecdsa")]
use {
    crate::{AffinePoint, ProjectivePoint, Scalar},
    core::borrow::Borrow,
    ecdsa_core::hazmat::{SignPrimitive, VerifyPrimitive},
    elliptic_curve::{ops::Invert, subtle::CtOption, FromBytes},
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

#[cfg(all(feature = "ecdsa", feature = "sha256"))]
impl ecdsa_core::hazmat::DigestPrimitive for NistP256 {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "ecdsa")]
impl SignPrimitive<NistP256> for Scalar {
    #[allow(clippy::many_single_char_names)]
    fn try_sign_prehashed<K>(&self, ephemeral_scalar: &K, z: &Scalar) -> Result<Signature, Error>
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
    fn verify_prehashed(&self, z: &Scalar, signature: &Signature) -> Result<(), Error> {
        let maybe_r =
            Scalar::from_bytes(signature.r()).and_then(|r| CtOption::new(r, !r.is_zero()));

        let maybe_s =
            Scalar::from_bytes(signature.s()).and_then(|s| CtOption::new(s, !s.is_zero()));

        // TODO(tarcieri): replace with into conversion when available (see subtle#73)
        let (r, s) = if maybe_r.is_some().into() && maybe_s.is_some().into() {
            (maybe_r.unwrap(), maybe_s.unwrap())
        } else {
            return Err(Error::new());
        };

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
    use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP256};

    #[cfg(feature = "rand")]
    use {
        crate::{BlindedScalar, Scalar},
        core::convert::TryInto,
        ecdsa_core::hazmat::SignPrimitive,
        elliptic_curve::{rand_core::OsRng, FromBytes},
    };

    mod signing {
        use super::{NistP256, ECDSA_TEST_VECTORS};
        ecdsa_core::new_signing_test!(NistP256, ECDSA_TEST_VECTORS);
    }

    mod verification {
        use super::{NistP256, ECDSA_TEST_VECTORS};
        ecdsa_core::new_verification_test!(NistP256, ECDSA_TEST_VECTORS);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn scalar_blinding() {
        let vector = &ECDSA_TEST_VECTORS[0];
        let d = Scalar::from_bytes(vector.d.try_into().unwrap()).unwrap();
        let k = Scalar::from_bytes(vector.k.try_into().unwrap()).unwrap();
        let k_blinded = BlindedScalar::new(k, &mut OsRng);
        let z = Scalar::from_bytes(vector.m.try_into().unwrap()).unwrap();
        let sig = d.try_sign_prehashed(&k_blinded, &z).unwrap();

        assert_eq!(vector.r, sig.r().as_slice());
        assert_eq!(vector.s, sig.s().as_slice());
    }
}
