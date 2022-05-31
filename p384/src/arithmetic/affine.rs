//! Affine points on the NIST P-384 elliptic curve.

#![allow(clippy::op_ref)]

use core::ops::{Mul, Neg};

use super::{FieldElement, ProjectivePoint, CURVE_EQUATION_A, CURVE_EQUATION_B};
use crate::{CompressedPoint, EncodedPoint, FieldBytes, NistP384, PublicKey, Scalar, U384};
use elliptic_curve::{
    bigint::Encoding,
    group::{prime::PrimeCurveAffine, GroupEncoding},
    sec1::{self, FromEncodedPoint, ToCompactEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    AffineArithmetic, AffineXCoordinate, Curve, DecompactPoint, DecompressPoint, Error, Result,
};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

impl AffineArithmetic for NistP384 {
    type AffinePoint = AffinePoint;
}

/// NIST P-384 (secp384r1) curve point expressed in affine coordinates.
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, the `Serialize` and
/// `Deserialize` traits are impl'd for this type.
///
/// The serialization uses the [SEC1] `Elliptic-Curve-Point-to-Octet-String`
/// encoding, serialized as binary.
///
/// When serialized with a text-based format, the SEC1 representation is
/// subsequently hex encoded.
///
/// [SEC1]: https://www.secg.org/sec1-v2.pdf
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct AffinePoint {
    /// x-coordinate
    pub x: FieldElement,

    /// y-coordinate
    pub y: FieldElement,

    /// Is this point the point at infinity? 0 = no, 1 = yes
    ///
    /// This is a proxy for [`Choice`], but uses `u8` instead to permit `const`
    /// constructors for `IDENTITY` and `GENERATOR`.
    pub infinity: u8,
}

impl AffinePoint {
    /// Base point of P-384.
    ///
    /// Defined in FIPS 186-4 § D.1.2.4:
    ///
    /// ```text
    /// Gₓ = aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
    ///      59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
    /// Gᵧ = 3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
    ///      e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f
    /// ```
    ///
    /// NOTE: coordinate field elements have been translated into the Montgomery
    /// domain.
    pub const GENERATOR: Self = Self {
        x: FieldElement(U384::from_be_hex("4d3aadc2299e1513812ff723614ede2b6454868459a30eff879c3afc541b4d6e20e378e2a0d6ce383dd0756649c0b528")),
        y: FieldElement(U384::from_be_hex("2b78abc25a15c5e9dd8002263969a840c6c3521968f4ffd98bade7562e83b050a1bfa8bf7bb4a9ac23043dad4b03a4fe")),
        infinity: 0,
    };

    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
        infinity: 1,
    };
}

impl PrimeCurveAffine for AffinePoint {
    type Curve = ProjectivePoint;
    type Scalar = Scalar;

    fn identity() -> AffinePoint {
        Self::IDENTITY
    }

    fn generator() -> AffinePoint {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        Choice::from(self.infinity)
    }

    fn to_curve(&self) -> ProjectivePoint {
        ProjectivePoint::from(*self)
    }
}

impl AffineXCoordinate<NistP384> for AffinePoint {
    fn x(&self) -> FieldBytes {
        self.x.to_sec1()
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &AffinePoint, b: &AffinePoint, choice: Choice) -> AffinePoint {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            infinity: u8::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &AffinePoint) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y) & self.infinity.ct_eq(&other.infinity)
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl DefaultIsZeroes for AffinePoint {}

impl Eq for AffinePoint {}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Mul<Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Mul<&Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: &Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    fn neg(self) -> Self::Output {
        AffinePoint {
            x: self.x,
            y: -self.y,
            infinity: self.infinity,
        }
    }
}

impl DecompressPoint<NistP384> for AffinePoint {
    fn decompress(x_bytes: &FieldBytes, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_sec1(*x_bytes).and_then(|x| {
            let alpha = x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                let y = FieldElement::conditional_select(
                    &(FieldElement::MODULUS - &beta),
                    &beta,
                    beta.is_odd().ct_eq(&y_is_odd),
                );

                Self { x, y, infinity: 0 }
            })
        })
    }
}

impl GroupEncoding for AffinePoint {
    type Repr = CompressedPoint;

    /// NOTE: not constant-time with respect to identity point
    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        EncodedPoint::from_bytes(bytes)
            .map(|point| CtOption::new(point, Choice::from(1)))
            .unwrap_or_else(|_| {
                // SEC1 identity encoding is technically 1-byte 0x00, but the
                // `GroupEncoding` API requires a fixed-width `Repr`
                let is_identity = bytes.ct_eq(&Self::Repr::default());
                CtOption::new(EncodedPoint::identity(), is_identity)
            })
            .and_then(|point| Self::from_encoded_point(&point))
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        let encoded = self.to_encoded_point(true);
        let mut result = CompressedPoint::default();
        result[..encoded.len()].copy_from_slice(encoded.as_bytes());
        result
    }
}

impl DecompactPoint<NistP384> for AffinePoint {
    fn decompact(x_bytes: &FieldBytes) -> CtOption<Self> {
        FieldElement::from_sec1(*x_bytes).and_then(|x| {
            let montgomery_y = (x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B).sqrt();
            montgomery_y.map(|montgomery_y| {
                // Convert to canonical form for comparisons
                let y = montgomery_y.to_canonical();
                let p_y = FieldElement::MODULUS - &y;
                // let (_, borrow) = p_y.informed_subtract(&y);
                let borrow = 0;
                let recovered_y = if borrow == 0 { y } else { p_y };
                AffinePoint {
                    x,
                    y: recovered_y.to_montgomery(),
                    infinity: 0,
                }
            })
        })
    }
}

impl FromEncodedPoint<NistP384> for AffinePoint {
    /// Attempts to parse the given [`EncodedPoint`] as an SEC1-encoded
    /// [`AffinePoint`].
    ///
    /// # Returns
    ///
    /// `None` value if `encoded_point` is not on the secp384r1 curve.
    fn from_encoded_point(encoded_point: &EncodedPoint) -> CtOption<Self> {
        match encoded_point.coordinates() {
            sec1::Coordinates::Identity => CtOption::new(Self::identity(), 1.into()),
            sec1::Coordinates::Compact { x } => AffinePoint::decompact(x),
            sec1::Coordinates::Compressed { x, y_is_odd } => {
                AffinePoint::decompress(x, Choice::from(y_is_odd as u8))
            }
            sec1::Coordinates::Uncompressed { x, y } => {
                let x = FieldElement::from_sec1(*x);
                let y = FieldElement::from_sec1(*y);

                x.and_then(|x| {
                    y.and_then(|y| {
                        // Check that the point is on the curve
                        let lhs = y * &y;
                        let rhs = x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B;
                        let point = AffinePoint { x, y, infinity: 0 };
                        CtOption::new(point, lhs.ct_eq(&rhs))
                    })
                })
            }
        }
    }
}

impl ToEncodedPoint<NistP384> for AffinePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        EncodedPoint::conditional_select(
            &EncodedPoint::from_affine_coordinates(&self.x.to_sec1(), &self.y.to_sec1(), compress),
            &EncodedPoint::identity(),
            self.is_identity(),
        )
    }
}

impl ToCompactEncodedPoint<NistP384> for AffinePoint {
    /// Serialize this value as a  SEC1 compact [`EncodedPoint`]
    fn to_compact_encoded_point(&self) -> CtOption<EncodedPoint> {
        // Convert to canonical form for comparisons
        let y = self.y.to_canonical();
        let (p_y, borrow) = FieldElement::MODULUS.informed_subtract(&y);
        assert_eq!(borrow, 0);
        let (_, borrow) = p_y.informed_subtract(&y);

        // Reuse the CompressedPoint type since it's the same size as a compact point
        let mut bytes = CompressedPoint::default();
        bytes[0] = sec1::Tag::Compact.into();
        let x = self.x.to_sec1();
        bytes[1..(<NistP384 as Curve>::UInt::BYTE_SIZE + 1)].copy_from_slice(x.as_slice());
        CtOption::new(
            EncodedPoint::from_bytes(bytes).expect("compact key"),
            borrow.ct_eq(&0),
        )
    }
}

impl TryFrom<EncodedPoint> for AffinePoint {
    type Error = Error;

    fn try_from(point: EncodedPoint) -> Result<AffinePoint> {
        AffinePoint::try_from(&point)
    }
}

impl TryFrom<&EncodedPoint> for AffinePoint {
    type Error = Error;

    fn try_from(point: &EncodedPoint) -> Result<AffinePoint> {
        Option::from(AffinePoint::from_encoded_point(point)).ok_or(Error)
    }
}

impl From<AffinePoint> for EncodedPoint {
    fn from(affine_point: AffinePoint) -> EncodedPoint {
        affine_point.to_encoded_point(false)
    }
}

impl From<PublicKey> for AffinePoint {
    fn from(public_key: PublicKey) -> AffinePoint {
        *public_key.as_affine()
    }
}

impl From<&PublicKey> for AffinePoint {
    fn from(public_key: &PublicKey) -> AffinePoint {
        AffinePoint::from(*public_key)
    }
}

impl TryFrom<AffinePoint> for PublicKey {
    type Error = Error;

    fn try_from(affine_point: AffinePoint) -> Result<PublicKey> {
        PublicKey::from_affine(affine_point)
    }
}

impl TryFrom<&AffinePoint> for PublicKey {
    type Error = Error;

    fn try_from(affine_point: &AffinePoint) -> Result<PublicKey> {
        PublicKey::try_from(*affine_point)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for AffinePoint {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.to_encoded_point(true).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for AffinePoint {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        EncodedPoint::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::{
        group::{prime::PrimeCurveAffine, GroupEncoding},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    };
    use hex_literal::hex;

    use super::AffinePoint;
    use crate::EncodedPoint;

    const UNCOMPRESSED_BASEPOINT: &[u8] = &hex!(
        "04 aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
         59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
         3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
         e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f"
    );

    const COMPRESSED_BASEPOINT: &[u8] = &hex!(
        "03 aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
         59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7"
    );

    #[test]
    fn uncompressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.into();
        assert_eq!(res, pubkey);
    }

    #[test]
    fn compressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.to_encoded_point(true);
        assert_eq!(res, pubkey);
    }

    #[test]
    fn uncompressed_to_compressed() {
        let encoded = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(true);

        assert_eq!(res.as_bytes(), COMPRESSED_BASEPOINT);
    }

    #[test]
    fn compressed_to_uncompressed() {
        let encoded = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(false);

        assert_eq!(res.as_bytes(), UNCOMPRESSED_BASEPOINT);
    }

    #[test]
    fn affine_negation() {
        let basepoint = AffinePoint::generator();
        assert_eq!(-(-basepoint), basepoint);
    }

    #[test]
    fn identity_encoding() {
        // This is technically an invalid SEC1 encoding, but is preferable to panicking.
        assert_eq!([0; 49], AffinePoint::IDENTITY.to_bytes().as_slice());
        assert!(bool::from(
            AffinePoint::from_bytes(&AffinePoint::IDENTITY.to_bytes())
                .unwrap()
                .is_identity()
        ))
    }
}
