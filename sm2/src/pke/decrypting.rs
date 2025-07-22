use core::fmt::{self, Debug};

use crate::Sm2;
use crate::{FieldBytes, NonZeroScalar, PublicKey, SecretKey};
#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use elliptic_curve::{
    CurveArithmetic, CurveGroup, Error, Result,
    sec1::{ModulusSize, ToEncodedPoint},
    subtle::{Choice, ConstantTimeEq},
};

use sm3::{
    Sm3,
    digest::{Digest, FixedOutputReset, Output, Update},
};

use super::{Cipher, encrypting::EncryptingKey, kdf};
/// Represents a decryption key used for decrypting messages using elliptic curve cryptography.
#[derive(Clone)]
pub struct DecryptingKey {
    secret_scalar: NonZeroScalar,
    encryting_key: EncryptingKey,
}

impl DecryptingKey {
    /// Creates a new `DecryptingKey` from a `SecretKey` with the default decryption mode (`C1C3C2`).
    pub fn new(secret_key: SecretKey) -> Self {
        Self::from_nonzero_scalar(secret_key.to_nonzero_scalar())
    }

    /// Create a signing key from a non-zero scalar.
    /// Creates a new `DecryptingKey` from a non-zero scalar and sets the decryption mode.
    pub fn from_nonzero_scalar(secret_scalar: NonZeroScalar) -> Self {
        Self {
            secret_scalar,
            encryting_key: EncryptingKey::new(PublicKey::from_secret_scalar(&secret_scalar)),
        }
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        Self::from_slice(bytes)
    }

    /// Parse signing key from big endian-encoded byte slice containing a secret
    /// scalar value.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let secret_scalar = NonZeroScalar::try_from(slice).map_err(|_| Error)?;
        Ok(Self::from_nonzero_scalar(secret_scalar))
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

    /// Get the [`EncryptingKey`] which corresponds to this [`DecryptingKey`].
    pub fn encrypting_key(&self) -> &EncryptingKey {
        &self.encryting_key
    }

    /// Decrypt the [`Cipher`] using the default digest algorithm [`Sm3`].
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, cipher: &Cipher<'_, Sm2, Sm3>) -> Result<Vec<u8>> {
        self.decrypt_digest::<Sm3>(cipher)
    }

    /// Decrypt the [`Cipher`] using the specified digest algorithm.
    #[cfg(feature = "alloc")]
    pub fn decrypt_digest<D: Digest + FixedOutputReset>(
        &self,
        cipher: &Cipher<'_, Sm2, D>,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0; cipher.c2.len()];
        self.decrypt_digest_into(cipher, &mut out)?;
        Ok(out)
    }

    /// Decrypt the [`Cipher`] using the default digest algorithm [`Sm3`].
    pub fn decrypt_into(&self, cipher: &Cipher<'_, Sm2, Sm3>, out: &mut [u8]) -> Result<usize> {
        self.decrypt_digest_into(cipher, out)
    }

    /// Decrypt the [`Cipher`] to out using the specified digest algorithm.
    /// The length of out is equal to the length of C2.
    /// * Note: buffer zones are prohibited from overlapping
    pub fn decrypt_digest_into<D: Digest + FixedOutputReset>(
        &self,
        cipher: &Cipher<'_, Sm2, D>,
        out: &mut [u8],
    ) -> Result<usize> {
        let scalar = self.as_nonzero_scalar();
        decrypt_into(scalar.as_ref(), cipher, out)
    }
}

//
// Other trait impls
//

impl AsRef<EncryptingKey> for DecryptingKey {
    fn as_ref(&self) -> &EncryptingKey {
        &self.encryting_key
    }
}

impl ConstantTimeEq for DecryptingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret_scalar.ct_eq(&other.secret_scalar)
    }
}

impl Debug for DecryptingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptingKey")
            .field("private_key", &self.secret_scalar.as_ref())
            // .field("encrypting_key", &self.encrypting_key())
            .finish_non_exhaustive()
    }
}

/// Constant-time comparison
impl Eq for DecryptingKey {}
impl PartialEq for DecryptingKey {
    fn eq(&self, other: &DecryptingKey) -> bool {
        self.ct_eq(other).into()
    }
}

fn decrypt_into<C, D>(
    secret_scalar: &C::Scalar,
    cipher: &Cipher<'_, C, D>,
    out: &mut [u8],
) -> Result<usize>
where
    C: CurveArithmetic,
    D: FixedOutputReset + Digest,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToEncodedPoint<C>,
{
    if out.len() < cipher.c2.len() {
        return Err(Error);
    }
    let out = &mut out[..cipher.c2.len()];

    let mut digest = D::new();

    // B3: compute [𝑑𝐵]𝐶1 = (𝑥2, 𝑦2)
    let c1_point = (C::ProjectivePoint::from(cipher.c1) * secret_scalar).to_affine();

    #[cfg(feature = "alloc")]
    let c2 = &cipher.c2;
    #[cfg(not(feature = "alloc"))]
    let c2 = cipher.c2;

    // B4: compute 𝑡 = 𝐾𝐷𝐹(𝑥2 ∥ 𝑦2, 𝑘𝑙𝑒𝑛)
    // B5: get 𝐶2 from 𝐶 and compute 𝑀′ = 𝐶2 ⊕ t
    kdf::<D, C>(&mut digest, c1_point, c2, out)?;

    // compute 𝑢 = 𝐻𝑎𝑠ℎ(𝑥2 ∥ 𝑀′∥ 𝑦2).
    let mut u = Output::<D>::default();
    let encode_point = c1_point.to_encoded_point(false);
    Update::update(&mut digest, encode_point.x().ok_or(Error)?);
    Update::update(&mut digest, out);
    Update::update(&mut digest, encode_point.y().ok_or(Error)?);
    FixedOutputReset::finalize_into_reset(&mut digest, &mut u);

    // If 𝑢 ≠ 𝐶3, output “ERROR” and exit
    if cipher.c3 != u {
        return Err(Error);
    }

    Ok(out.len())
}
