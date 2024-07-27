//! Support for signing Bign256 signatures.
//!
//! ## Algorithm
//!
//! ```text
//! 1. Set 𝐻 ← ℎ(𝑋).
//! 2. Generate 𝑘 ← rand(1,..,𝑞-1)
//! 3. Set 𝑅 ← 𝑘𝐺.
//! 4. Set 𝑆0 ← ⟨︀belt-hash(OID(ℎ) ‖ ⟨𝑅⟩2𝑙 ‖ 𝐻)⟩︀_𝑙.
//! 5. Set 𝑆1 ← ⟨︀(𝑘 − 𝐻 − (𝑆0 + 2^𝑙)𝑑) mod 𝑞⟩︀_2𝑙.
//! 6. Set 𝑆 ← 𝑆0 ‖ 𝑆1.
//! 7. Return S.
//! ```

#![allow(non_snake_case)]

use super::{Signature, VerifyingKey, BELT_OID};
use crate::{BignP256, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey};
use belt_hash::{BeltHash, Digest};
use core::fmt::{self, Debug};
use elliptic_curve::{
    array::{sizes::U32, typenum::Unsigned, Array},
    ops::{MulByGenerator, Reduce},
    point::AffineCoordinates,
    subtle::{Choice, ConstantTimeEq},
    Curve, Field, FieldBytesEncoding, PrimeField,
};
use signature::{hazmat::PrehashSigner, Error, KeypairRef, Result, Signer};

/// BignP256 secret key used for signing messages and producing signatures.
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
    pub fn new(secret_key: &SecretKey) -> Result<Self> {
        Self::from_nonzero_scalar(secret_key.to_nonzero_scalar())
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        Self::from_slice(bytes)
    }

    /// Parse signing key from big endian-encoded byte slice containing a secret
    /// scalar value.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let secret_scalar = NonZeroScalar::try_from(slice).map_err(|_| Error::new())?;
        Self::from_nonzero_scalar(secret_scalar)
    }

    /// Create a signing key from a non-zero scalar.
    pub fn from_nonzero_scalar(secret_scalar: NonZeroScalar) -> Result<Self> {
        let public_key = PublicKey::from_secret_scalar(&secret_scalar);
        let verifying_key = VerifyingKey::new(public_key)?;
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
}

//
// `*Signer` trait impls
//

impl PrehashSigner<Signature> for SigningKey {
    #[allow(deprecated)] // clone_from_slice
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        if prehash.len() != <BignP256 as Curve>::FieldBytesSize::USIZE {
            return Err(Error::new());
        }
        let mut h_word: Array<u8, U32> = Array::clone_from_slice(prehash);
        h_word.reverse();

        let h = Scalar::reduce_bytes(&h_word);

        //2. Generate 𝑘 ← rand(1,..,𝑞-1)
        let k = Scalar::from_repr(rfc6979::generate_k::<BeltHash, _>(
            &self.secret_scalar.to_repr(),
            &FieldBytesEncoding::<BignP256>::encode_field_bytes(&BignP256::ORDER),
            &h.to_bytes(),
            &[],
        ))
        .unwrap();

        // 3. Set 𝑅 ← 𝑘𝐺.
        let mut R: Array<u8, _> = ProjectivePoint::mul_by_generator(&k).to_affine().x();
        R.reverse();

        // 4. Set 𝑆0 ← ⟨︀belt-hash(OID(ℎ) ‖ ⟨𝑅⟩2𝑙 ‖ 𝐻)⟩︀_𝑙.
        let mut hasher = BeltHash::new();
        hasher.update(BELT_OID);
        hasher.update(R);
        hasher.update(prehash);

        let mut s0 = hasher.finalize();
        s0[16..].fill(0x00);
        s0.reverse();

        let s0_scalar = Scalar::from_slice(&s0).map_err(|_| Error::new())?;

        let right = s0_scalar
            .add(&Scalar::from_u64(2).pow([128, 0, 0, 0]))
            .multiply(self.as_nonzero_scalar());

        // 5. Set 𝑆1 ← ⟨︀(𝑘 − 𝐻 − (𝑆0 + 2^𝑙)𝑑) mod 𝑞⟩︀_2𝑙.
        let s1 = k.sub(&h).sub(&right);

        // 6. Set 𝑆 ← 𝑆0 ‖ 𝑆1.
        // 7. Return S.
        Signature::from_scalars(s0_scalar, s1)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature> {
        // 1. Set 𝐻 ← ℎ(𝑋).
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
