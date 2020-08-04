//! ECDSA signer

use super::{recoverable, Error, Signature};
use crate::{ProjectivePoint, PublicKey, Scalar, ScalarBytes, Secp256k1, SecretKey};
use core::borrow::Borrow;
use ecdsa_core::{hazmat::SignPrimitive, signature::RandomizedSigner};
use elliptic_curve::{
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
};

#[cfg(debug_assertions)]
use crate::{ecdsa::signature::Verifier as _, ecdsa::Verifier};

/// ECDSA/secp256k1 signer
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub struct Signer {
    /// Core ECDSA signer
    signer: ecdsa_core::Signer<Secp256k1>,

    /// Public key
    public_key: PublicKey,
}

impl Signer {
    /// Create a new signer
    pub fn new(secret_key: &SecretKey) -> Result<Self, Error> {
        let signer = ecdsa_core::Signer::new(secret_key)?;
        let public_key = PublicKey::from_secret_key(secret_key, true).map_err(|_| Error::new())?;
        Ok(Self { signer, public_key })
    }

    /// Get the public key for this signer
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl RandomizedSigner<Signature> for Signer {
    fn try_sign_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> Result<Signature, Error> {
        let signature = self
            .signer
            .try_sign_with_rng(rng, msg)
            .and_then(|sig| super::normalize_s(&sig))?;

        #[cfg(debug_assertions)]
        assert!(Verifier::new(&self.public_key)
            .expect("invalid public key")
            .verify(msg, &signature)
            .is_ok());

        Ok(signature)
    }
}

impl RandomizedSigner<recoverable::Signature> for Signer {
    fn try_sign_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> Result<recoverable::Signature, Error> {
        let signature = self.try_sign_with_rng(rng, msg)?;

        // TODO(tarcieri): more efficient method of computing recovery ID
        recoverable::Signature::from_trial_recovery(&self.public_key, msg, &signature)
    }
}

impl From<&Signer> for PublicKey {
    fn from(signer: &Signer) -> PublicKey {
        signer.public_key
    }
}

impl SignPrimitive<Secp256k1> for Scalar {
    #[allow(clippy::many_single_char_names)]
    fn try_sign_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &ScalarBytes,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::ecdsa::ECDSA_TEST_VECTORS;
    ecdsa_core::new_signing_test!(ECDSA_TEST_VECTORS);
}
