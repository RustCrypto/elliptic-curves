//! Support for verifying Bign256 signatures.
//!
//! ## Algorithm
//!
//! ```text
//! 1. If |𝑆| != 3𝑙, return NO.
//! 2. Assume 𝑆 as 𝑆 = 𝑆0 ‖ 𝑆1, where 𝑆0 ∈ {0, 1}^𝑙, 𝑆1 ∈ {0, 1}^2𝑙.
//! 3. If 𝑆1 ⩾ 𝑞, return NO.
//! 4. Set 𝐻 ← ℎ(𝑋).
//! 5. Set 𝑅 ← (︀(𝑆1 + 𝐻) mod 𝑞)︀𝐺 + (𝑆0 + 2𝑙)𝑄.
//! 6. If 𝑅 = 𝑂, return NO.
//! 7. Set 𝑡 ← ⟨︀belt-hash(OID(ℎ) ‖ ⟨𝑅⟩^2𝑙 ‖ 𝐻) ⟩︀^𝑙.
//! 8. If 𝑆0 != 𝑡, return NO.
//! 9. Return YES.
//! ```

use super::{Signature, BELT_OID};
use crate::{
    AffinePoint, BignP256, EncodedPoint, FieldBytes, Hash, ProjectivePoint, PublicKey, Scalar,
};
use belt_hash::{
    digest::{Digest, FixedOutput},
    BeltHash,
};
use crypto_bigint::{consts::U32, generic_array::GenericArray};
use elliptic_curve::{
    generic_array::typenum::Unsigned,
    group::GroupEncoding,
    ops::{LinearCombination, Reduce},
    sec1::ToEncodedPoint,
    Curve, Field, Group,
};
use signature::{hazmat::PrehashVerifier, Error, Result, Verifier};

/// Bign256 public key used for verifying signatures are valid for a given
/// message.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for verifying:
///
/// - [`Verifier`]: verify a message against a provided key and signature
/// - [`PrehashVerifier`]: verify the low-level raw output bytes of a message digest
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, it provides support for
/// serializing and deserializing ECDSA signatures using the `Serialize` and
/// `Deserialize` traits.
///
/// The serialization leverages the encoding used by the [`PublicKey`] type,
/// which is a binary-oriented ASN.1 DER encoding.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Signer's public key.
    public_key: PublicKey,
}

impl VerifyingKey {
    /// Initialize [`VerifyingKey`] from a signer's distinguishing identifier
    /// and public key.
    pub fn new(public_key: PublicKey) -> Result<Self> {
        Ok(Self { public_key })
    }

    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(affine: AffinePoint) -> Result<Self> {
        let public_key = PublicKey::from_affine(affine).map_err(|_| Error::new())?;
        Self::new(public_key)
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint {
        self.public_key.as_affine()
    }

    /// Compute message hash `e` according to [STB 34.101.31-2020 § 7.8]
    ///
    /// [STB 34.101.31-2020 § 7.8]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
    pub(crate) fn hash_msg(&self, msg: &[u8]) -> Hash {
        let mut hasher = BeltHash::new();
        hasher.update(msg);
        hasher.finalize_fixed()
    }

    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::new())?;
        Self::new(public_key)
    }

    /// Convert this [`VerifyingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    #[cfg(feature = "alloc")]
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.public_key.to_sec1_bytes()
    }
}

//
// `*Verifier` trait impls
//
impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> Result<()> {
        // 1. If |𝑆| != 3𝑙, return NO.
        if prehash.len() != <BignP256 as Curve>::FieldBytesSize::USIZE {
            return Err(Error::new());
        }
        // 2. Assume 𝑆 as 𝑆 = 𝑆0 ‖ 𝑆1, где 𝑆0 ∈ {0, 1}^𝑙, 𝑆1 ∈ {0, 1}^2𝑙.
        let s0 = signature.s0();
        // 3. If 𝑆1 ⩾ 𝑞, return NO.
        let s1 = signature.s1();

        let mut hash: GenericArray<u8, U32> = GenericArray::clone_from_slice(prehash);
        hash.reverse();

        let hw = Scalar::reduce_bytes(FieldBytes::from_slice(&hash));
        let left = s1.add(&hw);

        let right = s0.add(&Scalar::from_u64(2).pow([128, 0, 0, 0]));

        // 5. Set 𝑅 ← (︀(𝑆1 + 𝐻) mod 𝑞)︀𝐺 + (𝑆0 + 2𝑙)𝑄.
        let r = ProjectivePoint::lincomb(
            &ProjectivePoint::generator(),
            &left,
            &self.public_key.to_projective(),
            &right,
        );

        // 6. If 𝑅 = 𝑂, return NO.
        if r.is_identity().into() {
            return Err(Error::new());
        }

        let mut r_bytes = r.to_bytes();
        r_bytes.reverse();

        let mut hasher = BeltHash::new();
        hasher.update(BELT_OID);
        hasher.update(&r_bytes[0..32]);
        hasher.update(prehash);

        // 7. Set 𝑡 ← ⟨︀belt-hash(OID(ℎ) ‖ ⟨𝑅⟩^2𝑙 ‖ 𝐻) ⟩︀^𝑙.
        let t = hasher.finalize();

        let s0 = &mut s0.to_bytes()[16..];
        s0.reverse();

        // 8. If 𝑆0 != 𝑡, return NO.
        if s0 == &t.as_slice()[..16] {
            // 9. Return YES.
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        // 4. Set 𝐻 ← ℎ(𝑋).
        let hash = self.hash_msg(msg);
        self.verify_prehash(&hash, signature)
    }
}

#[cfg(test)]
mod test {
    use crate::dsa::verifying::VerifyingKey;
    use crate::dsa::Signature;
    use crate::PublicKey;

    use signature::Verifier;

    #[test]
    fn test() {
        let data: [u8; 48] = [
            0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A,
            0x5D, 0xE4, 0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2,
            0x02, 0xFD, 0xCE, 0x0D, 0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67,
            0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
        ];

        let xq = [
            0xBD, 0x1A, 0x56, 0x50, 0x17, 0x9D, 0x79, 0xE0, 0x3F, 0xCE, 0xE4, 0x9D, 0x4C, 0x2B,
            0xD5, 0xDD, 0xF5, 0x4C, 0xE4, 0x6D, 0x0C, 0xF1, 0x1E, 0x4F, 0xF8, 0x7B, 0xF7, 0xA8,
            0x90, 0x85, 0x7F, 0xD0,
        ];

        let yq = [
            0x7A, 0xC6, 0xA6, 0x03, 0x61, 0xE8, 0xC8, 0x17, 0x34, 0x91, 0x68, 0x6D, 0x46, 0x1B,
            0x28, 0x26, 0x19, 0x0C, 0x2E, 0xDA, 0x59, 0x09, 0x05, 0x4A, 0x9A, 0xB8, 0x4D, 0x2A,
            0xB9, 0xD9, 0x9A, 0x90,
        ];

        let s = [
            0x47, 0xA6, 0x3C, 0x8B, 0x9C, 0x93, 0x6E, 0x94, 0xB5, 0xFA, 0xB3, 0xD9, 0xCB, 0xD7,
            0x83, 0x66, 0x29, 0x0F, 0x32, 0x10, 0xE1, 0x63, 0xEE, 0xC8, 0xDB, 0x4E, 0x92, 0x1E,
            0x84, 0x79, 0xD4, 0x13, 0x8F, 0x11, 0x2C, 0xC2, 0x3E, 0x6D, 0xCE, 0x65, 0xEC, 0x5F,
            0xF2, 0x1D, 0xF4, 0x23, 0x1C, 0x28,
        ];

        let mut key = [&[0x04], &xq[..], &yq[..]].concat();

        key[1..33].reverse();
        key[33..65].reverse();
        let pk = PublicKey::from_sec1_bytes(&key).unwrap();
        let vk = VerifyingKey::new(pk).unwrap();

        let sig = Signature::from_slice(&s).unwrap();

        vk.verify(&data, &sig).unwrap();
    }
}

//
// Other trait impls
//

impl AsRef<AffinePoint> for VerifyingKey {
    fn as_ref(&self) -> &AffinePoint {
        self.as_affine()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(verifying_key: VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(verifying_key: &VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl ToEncodedPoint<BignP256> for VerifyingKey {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.as_affine().to_encoded_point(compress)
    }
}
