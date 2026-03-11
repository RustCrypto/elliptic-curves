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

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use super::{BELT_OID, Signature};
use crate::{
    AffinePoint, BignP256, FieldBytes, Hash, ProjectivePoint, PublicKey, Scalar, Sec1Point,
};
use belt_hash::{
    BeltHash,
    digest::{Digest, FixedOutput},
};
use elliptic_curve::{
    Curve, Field, Group,
    array::{Array, sizes::U32, typenum::Unsigned},
    ops::{LinearCombination, Reduce},
    point::AffineCoordinates,
    sec1::ToSec1Point,
};
use signature::{Error, MultipartVerifier, Result, Verifier, hazmat::PrehashVerifier};

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
#[derive(Clone, Copy, Debug)]
pub struct VerifyingKey {
    /// Signer's public key.
    public_key: PublicKey,
}

impl VerifyingKey {
    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(affine: AffinePoint) -> Result<Self> {
        Ok(Self {
            public_key: PublicKey::from_affine(affine).map_err(|_| Error::new())?,
        })
    }

    /// Parse a [`VerifyingKey`] from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            public_key: PublicKey::from_bytes(bytes).map_err(|_| Error::new())?,
        })
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint {
        self.public_key.as_affine()
    }

    /// Compute message hash `e` according to [STB 34.101.31-2020 § 7.8]
    ///
    /// [STB 34.101.31-2020 § 7.8]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
    pub(crate) fn hash_msg(&self, msg: &[&[u8]]) -> Hash {
        let mut hasher = BeltHash::new();
        msg.iter().for_each(|slice| hasher.update(slice));
        hasher.finalize_fixed()
    }

    /// Serialize the [`VerifyingKey`] as a byte array.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.public_key.to_bytes()
    }
}

//
// `*Verifier` trait impls
//
impl PrehashVerifier<Signature> for VerifyingKey {
    #[allow(deprecated)] // clone_from_slice
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> Result<()> {
        // 1. If |𝑆| != 3𝑙, return NO.
        if prehash.len() != <BignP256 as Curve>::FieldBytesSize::USIZE {
            return Err(Error::new());
        }
        // 2. Assume 𝑆 as 𝑆 = 𝑆0 ‖ 𝑆1, где 𝑆0 ∈ {0, 1}^𝑙, 𝑆1 ∈ {0, 1}^2𝑙.
        let s0 = signature.s0();
        // 3. If 𝑆1 ⩾ 𝑞, return NO.
        let s1 = signature.s1();

        let hash: Array<u8, U32> = Array::clone_from_slice(prehash);

        let hw = Scalar::reduce(FieldBytes::from_slice(&hash));
        let left = s1.add(&hw);

        let right = s0.add(&Scalar::from_u64(2).pow([128, 0, 0, 0]));

        // 5. Set 𝑅 ← (︀(𝑆1 + 𝐻) mod 𝑞)︀𝐺 + (𝑆0 + 2𝑙)𝑄.
        let r = ProjectivePoint::lincomb(&[
            (ProjectivePoint::generator(), left),
            (self.public_key.to_projective(), right),
        ]);

        // 6. If 𝑅 = 𝑂, return NO.
        if r.is_identity().into() {
            return Err(Error::new());
        }

        let r = r.to_affine();
        let rx = r.x();

        let mut hasher = BeltHash::new();
        hasher.update(BELT_OID);
        hasher.update(rx);
        hasher.update(prehash);

        // 7. Set 𝑡 ← ⟨︀belt-hash(OID(ℎ) ‖ ⟨𝑅⟩^2𝑙 ‖ 𝐻) ⟩︀^𝑙.
        let t = hasher.finalize();

        let s0 = &mut s0.to_bytes()[..16];

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
        self.multipart_verify(&[msg], signature)
    }
}

impl MultipartVerifier<Signature> for VerifyingKey {
    fn multipart_verify(&self, msg: &[&[u8]], signature: &Signature) -> Result<()> {
        // 4. Set 𝐻 ← ℎ(𝑋).
        let hash = self.hash_msg(msg);
        self.verify_prehash(&hash, signature)
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

impl From<PublicKey> for VerifyingKey {
    fn from(public_key: PublicKey) -> VerifyingKey {
        VerifyingKey { public_key }
    }
}

impl From<&PublicKey> for VerifyingKey {
    fn from(public_key: &PublicKey) -> VerifyingKey {
        VerifyingKey::from(*public_key)
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(verifying_key: VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(verifying_key: &VerifyingKey) -> PublicKey {
        PublicKey::from(*verifying_key)
    }
}

impl ToSec1Point<BignP256> for VerifyingKey {
    fn to_sec1_point(&self, compress: bool) -> Sec1Point {
        self.as_affine().to_sec1_point(compress)
    }
}
