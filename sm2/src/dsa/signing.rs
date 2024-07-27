//! Support for SM2DSA signing.
//!
//! ## Algorithm
//!
//! ```text
//! A1: set M~=ZA || M
//! A2: calculate e=Hv(M~)
//! A3: pick a random number k in [1, n-1] via a random number generator
//! A4: calculate the elliptic curve point (x1, y1)=[k]G
//! A5: calculate r=(e+x1) modn, return to A3 if r=0 or r+k=n
//! A6: calculate s=((1+dA)^(-1)*(k-r*dA)) modn, return to A3 if s=0
//! A7: the digital signature of M is (r, s)
//! ```

#![allow(non_snake_case)]

use super::{Signature, VerifyingKey};
use crate::{
    DistId, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey, Sm2,
};
use core::fmt::{self, Debug};
use elliptic_curve::{
    array::typenum::Unsigned,
    ops::{MulByGenerator, Reduce},
    point::AffineCoordinates,
    subtle::{Choice, ConstantTimeEq},
    Curve, FieldBytesEncoding, PrimeField,
};
use signature::{
    hazmat::{PrehashSigner, RandomizedPrehashSigner},
    rand_core::CryptoRngCore,
    Error, KeypairRef, RandomizedSigner, Result, Signer,
};
use sm3::Sm3;

/// SM2DSA secret key used for signing messages and producing signatures.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for signing:
///
/// - [`Signer`]: sign a message using this key
/// - [`PrehashSigner`]: sign the low-level raw output bytes of a message digest
#[derive(Clone)]
pub struct SigningKey {
    /// Secret key.
    secret_scalar: NonZeroScalar,

    /// Verifying key for this signing key.
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Create signing key from a signer's distinguishing identifier and
    /// secret key.
    pub fn new(distid: &DistId, secret_key: &SecretKey) -> Result<Self> {
        Self::from_nonzero_scalar(distid, secret_key.to_nonzero_scalar())
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(distid: &DistId, bytes: &FieldBytes) -> Result<Self> {
        Self::from_slice(distid, bytes)
    }

    /// Parse signing key from big endian-encoded byte slice containing a secret
    /// scalar value.
    pub fn from_slice(distid: &DistId, slice: &[u8]) -> Result<Self> {
        let secret_scalar = NonZeroScalar::try_from(slice).map_err(|_| Error::new())?;
        Self::from_nonzero_scalar(distid, secret_scalar)
    }

    /// Create a signing key from a non-zero scalar.
    pub fn from_nonzero_scalar(distid: &DistId, secret_scalar: NonZeroScalar) -> Result<Self> {
        let public_key = PublicKey::from_secret_scalar(&secret_scalar);
        let verifying_key = VerifyingKey::new(distid, public_key)?;
        Ok(Self {
            secret_scalar,
            verifying_key,
        })
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_scalar.to_bytes()
    }

    /// Borrow the secret [`NonZeroScalar`] value for this key.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        &self.secret_scalar
    }

    /// Get the [`VerifyingKey`] which corresponds to this [`SigningKey`].
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the distinguishing identifier for this key.
    #[cfg(feature = "alloc")]
    pub fn distid(&self) -> &DistId {
        self.verifying_key.distid()
    }
}

//
// `*Signer` trait impls
//

impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        sign_prehash_rfc6979(&self.secret_scalar, prehash, &[])
    }
}

impl RandomizedPrehashSigner<Signature> for SigningKey {
    fn sign_prehash_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<Signature> {
        let mut data = FieldBytes::default();
        rng.try_fill_bytes(&mut data)?;
        sign_prehash_rfc6979(&self.secret_scalar, prehash, &data)
    }
}

impl RandomizedSigner<Signature> for SigningKey {
    fn try_sign_with_rng(&self, rng: &mut impl CryptoRngCore, msg: &[u8]) -> Result<Signature> {
        // A1: set M~=ZA || M
        let hash = self.verifying_key.hash_msg(msg);
        self.sign_prehash_with_rng(rng, &hash)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature> {
        // A1: set M~=ZA || M
        let hash = self.verifying_key.hash_msg(msg);
        self.sign_prehash(&hash)
    }
}

//
// Other trait impls
//

impl AsRef<VerifyingKey> for SigningKey {
    fn as_ref(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret_scalar.ct_eq(&other.secret_scalar)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

/// Constant-time comparison
impl Eq for SigningKey {}
impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        self.ct_eq(other).into()
    }
}

impl KeypairRef for SigningKey {
    type VerifyingKey = VerifyingKey;
}

/// Compute a signature using RFC6979 to deterministically derive `k`.
fn sign_prehash_rfc6979(secret_scalar: &Scalar, prehash: &[u8], data: &[u8]) -> Result<Signature> {
    if prehash.len() != <Sm2 as Curve>::FieldBytesSize::USIZE {
        return Err(Error::new());
    }

    // A2: calculate e=Hv(M~)
    #[allow(deprecated)] // from_slice
    let e = Scalar::reduce_bytes(FieldBytes::from_slice(prehash));

    // A3: pick a random number k in [1, n-1] via a random number generator
    let k = Scalar::from_repr(rfc6979::generate_k::<Sm3, _>(
        &secret_scalar.to_repr(),
        &FieldBytesEncoding::<Sm2>::encode_field_bytes(&Sm2::ORDER),
        &e.to_bytes(),
        data,
    ))
    .unwrap();

    // A4: calculate the elliptic curve point (x1, y1)=[k]G
    let R = ProjectivePoint::mul_by_generator(&k).to_affine();

    // A5: calculate r=(e+x1) modn, return to A3 if r=0 or r+k=n
    let r = e + Scalar::reduce_bytes(&R.x());
    if bool::from(r.is_zero() | (r + k).ct_eq(&Scalar::ZERO)) {
        return Err(Error::new());
    }

    // A6: calculate s=((1+dA)^(-1)*(k-r*dA)) modn, return to A3 if s=0
    let d_plus_1_inv =
        Option::<Scalar>::from((secret_scalar + &Scalar::ONE).invert()).ok_or_else(Error::new)?;

    let s = d_plus_1_inv * (k - (r * secret_scalar));

    // A7: the digital signature of M is (r, s)
    Signature::from_scalars(r, s)
}
