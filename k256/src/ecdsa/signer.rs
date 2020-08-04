//! ECDSA signer

use super::{recoverable, Error, Signature};
use crate::{ProjectivePoint, PublicKey, Scalar, ScalarBytes, Secp256k1, SecretKey};
use core::borrow::Borrow;
use ecdsa_core::{hazmat::RecoverableSignPrimitive, signature::RandomizedSigner};
use elliptic_curve::{
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
    secret_key::FromSecretKey,
    zeroize::Zeroizing,
    Generate,
};
use sha2::{Digest, Sha256};

#[cfg(debug_assertions)]
use crate::{ecdsa::signature::Verifier as _, ecdsa::Verifier};

/// ECDSA/secp256k1 signer
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub struct Signer {
    /// Secret scalar value
    secret_key: SecretKey,

    /// Public key
    public_key: PublicKey,
}

impl Signer {
    /// Create a new signer
    pub fn new(secret_key: &SecretKey) -> Result<Self, Error> {
        let public_key = PublicKey::from_secret_key(secret_key, true).map_err(|_| Error::new())?;
        Ok(Self {
            secret_key: secret_key.clone(),
            public_key,
        })
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
        let signer = ecdsa_core::Signer::new(&self.secret_key)?;

        let signature = signer
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
        let d = Scalar::from_secret_key(&self.secret_key).unwrap();
        let k = Zeroizing::new(Scalar::generate(rng));
        let z = Sha256::new().chain(msg).finalize();
        let (signature, is_r_odd) = d.try_sign_recoverable_prehashed(&*k, &z)?;
        let normalized_signature = super::normalize_s(&signature)?;
        let is_s_high = normalized_signature != signature;
        let recovery_id = recoverable::Id((is_r_odd ^ is_s_high) as u8);

        Ok(recoverable::Signature::new(
            &normalized_signature,
            recovery_id,
        ))
    }
}

impl From<&Signer> for PublicKey {
    fn from(signer: &Signer) -> PublicKey {
        signer.public_key
    }
}

impl RecoverableSignPrimitive<Secp256k1> for Scalar {
    #[allow(non_snake_case, clippy::many_single_char_names)]
    fn try_sign_recoverable_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &ScalarBytes,
    ) -> Result<(Signature, bool), Error>
    where
        K: Borrow<Scalar> + Invert<Output = Scalar>,
    {
        let k_inverse = ephemeral_scalar.invert();
        let k = ephemeral_scalar.borrow();

        if k_inverse.is_none().into() || k.is_zero().into() {
            return Err(Error::new());
        }

        let k_inverse = k_inverse.unwrap();

        // Compute 𝐑 = 𝑘×𝑮
        let R = (ProjectivePoint::generator() * k).to_affine().unwrap();

        // Lift x-coordinate of 𝐑 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Scalar::from_bytes_reduced(&R.x.to_bytes());

        // Reduce message hash to an element of the scalar field
        let z = Scalar::from_bytes_reduced(hashed_msg.as_ref());

        // Compute `s` as a signature over `r` and `z`.
        let s = k_inverse * &(z + &(r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        let signature = Signature::from_scalars(&r.into(), &s.into());
        let r_is_odd = R.y.is_odd();
        Ok((signature, r_is_odd.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::ecdsa::ECDSA_TEST_VECTORS;
    use ecdsa_core::hazmat::SignPrimitive;
    ecdsa_core::new_signing_test!(ECDSA_TEST_VECTORS);
}
