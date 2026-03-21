#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};
use core::fmt::{self, Debug};
#[cfg(all(feature = "alloc", feature = "der"))]
use der::Decode;
use elliptic_curve::{
    CurveArithmetic, CurveGroup, Error, Result,
    sec1::{Coordinates, ModulusSize, ToSec1Point},
    subtle::{Choice, ConstantTimeEq},
};
use sm3::digest::{Digest, FixedOutputReset, Output, Update};

use crate::{
    FieldBytes, NonZeroScalar, PublicKey, SecretKey,
    pke::{Cipher, EncryptingKey, Mode},
};

/// Represents a decryption key used for decrypting messages using elliptic curve cryptography.
#[derive(Clone)]
pub struct DecryptingKey {
    secret_scalar: NonZeroScalar,
    encrypting_key: EncryptingKey,
    #[allow(unused)]
    mode: Mode,
}

impl DecryptingKey {
    /// Creates a new `DecryptingKey` from a `SecretKey` with the default decryption mode (`C1C3C2`).
    pub fn new(secret_key: SecretKey) -> Self {
        Self::new_with_mode(secret_key.to_nonzero_scalar(), Default::default())
    }

    /// Creates a new `DecryptingKey` from a non-zero scalar and sets the decryption mode.
    pub fn new_with_mode(secret_scalar: NonZeroScalar, mode: Mode) -> Self {
        Self {
            secret_scalar,
            encrypting_key: EncryptingKey::new_with_mode(
                PublicKey::from_secret_scalar(&secret_scalar),
                mode,
            ),
            mode,
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
        Self::from_nonzero_scalar(secret_scalar)
    }

    /// Create a signing key from a non-zero scalar.
    pub fn from_nonzero_scalar(secret_scalar: NonZeroScalar) -> Result<Self> {
        Ok(Self::new_with_mode(secret_scalar, Default::default()))
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
        &self.encrypting_key
    }

    /// Decrypts a ciphertext in-place using the default digest algorithm (`Sm3`).
    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_digest::<sm3::Sm3>(ciphertext)
    }

    /// Decrypts a ciphertext in-place using the specified digest algorithm.
    #[cfg(feature = "alloc")]
    pub fn decrypt_digest<D>(&self, ciphertext: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        let cipher = Cipher::<crate::Sm2, D>::from_slice(ciphertext, self.mode)?;
        self.decrypt_cipher(&cipher)
    }

    /// Decrypts a ciphertext in-place from ASN.1 format using the default digest algorithm (`Sm3`).
    #[cfg(all(feature = "alloc", feature = "der"))]
    pub fn decrypt_der(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_der_digest::<sm3::Sm3>(ciphertext)
    }

    /// Decrypts a ciphertext in-place from ASN.1 format using the specified digest algorithm.
    #[cfg(all(feature = "alloc", feature = "der"))]
    pub fn decrypt_der_digest<D>(&self, ciphertext: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        let cipher = Cipher::<crate::Sm2, D>::from_der(ciphertext)
            .map_err(elliptic_curve::pkcs8::Error::from)?;
        self.decrypt_cipher(&cipher)
    }

    /// Decrypts a message using a specified digest algorithm from a `Cipher` object.
    #[cfg(feature = "alloc")]
    pub fn decrypt_cipher<'a, D>(&self, cipher: &Cipher<'a, crate::Sm2, D>) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        let mut buf = vec![0; cipher.c2.len()];
        let _size = self.decrypt_cipher_with_buf::<D>(cipher, &mut buf)?;
        Ok(buf)
    }

    /// Decrypts a message using a specified digest algorithm from a `Cipher` object,   
    /// storing the plaintext in the provided buffer and returning the number of bytes written.
    pub fn decrypt_cipher_with_buf<'a, D>(
        &self,
        cipher: &Cipher<'a, crate::Sm2, D>,
        buf: &mut [u8],
    ) -> Result<usize>
    where
        D: Digest + FixedOutputReset,
    {
        decrypt::<crate::Sm2, D>(&self.secret_scalar, cipher, buf)
    }
}

//
// Other trait impls
//

impl AsRef<EncryptingKey> for DecryptingKey {
    fn as_ref(&self) -> &EncryptingKey {
        &self.encrypting_key
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
            .field("encrypting_key", &self.encrypting_key())
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

fn decrypt<C, D>(
    secret_scalar: &C::Scalar,
    cipher: &Cipher<'_, C, D>,
    out: &mut [u8],
) -> Result<usize>
where
    C: CurveArithmetic,
    D: FixedOutputReset + Digest,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C>,
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
    crate::pke::kdf::<D, C>(&mut digest, c1_point, c2, out)?;

    // compute 𝑢 = 𝐻𝑎𝑠ℎ(𝑥2 ∥ 𝑀′∥ 𝑦2).
    let mut u = Output::<D>::default();
    let encode_point = c1_point.to_sec1_point(false);
    let (x, y) = match encode_point.coordinates() {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => unreachable!(),
    };
    Update::update(&mut digest, x);
    Update::update(&mut digest, out);
    Update::update(&mut digest, y);
    FixedOutputReset::finalize_into_reset(&mut digest, &mut u);

    // If 𝑢 ≠ 𝐶3, output “ERROR” and exit
    if cipher.c3 != u {
        return Err(Error);
    }

    Ok(out.len())
}
