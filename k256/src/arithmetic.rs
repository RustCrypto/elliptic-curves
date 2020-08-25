//! A pure-Rust implementation of group operations on secp256k1.

pub(crate) mod field;
pub(crate) mod scalar;

mod util;

use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use elliptic_curve::{
    generic_array::arr,
    point::Generator,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    weierstrass::point::Decompress,
    Arithmetic,
};

use crate::{ElementBytes, EncodedPoint, Secp256k1};
use field::FieldElement;
use scalar::{NonZeroScalar, Scalar};

#[cfg(feature = "zeroize")]
use elliptic_curve::zeroize::Zeroize;

const CURVE_EQUATION_B_SINGLE: u32 = 7u32;

#[rustfmt::skip]
pub(crate) const CURVE_EQUATION_B: FieldElement = FieldElement::from_bytes_unchecked(&[
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, CURVE_EQUATION_B_SINGLE as u8,
]);

#[rustfmt::skip]
#[cfg(feature = "endomorphism-mul")]
const ENDOMORPHISM_BETA: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10,
    0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
    0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95,
    0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
]);

impl Arithmetic for Secp256k1 {
    type Scalar = Scalar;
    type AffinePoint = AffinePoint;
}

/// A point on the secp256k1 curve in affine coordinates.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct AffinePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &AffinePoint, b: &AffinePoint, choice: Choice) -> AffinePoint {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &AffinePoint) -> Choice {
        (self.x.negate(1) + &other.x).normalizes_to_zero()
            & (self.y.negate(1) + &other.y).normalizes_to_zero()
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl Generator for AffinePoint {
    /// Returns the base point of SECP256k1.
    fn generator() -> AffinePoint {
        // SECP256k1 basepoint in affine coordinates:
        // x = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
        // y = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
        AffinePoint {
            x: FieldElement::from_bytes(&arr![u8;
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98
            ])
            .unwrap(),
            y: FieldElement::from_bytes(&arr![u8;
                0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
                0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
                0xfb, 0x10, 0xd4, 0xb8
            ])
            .unwrap(),
        }
    }
}

impl Decompress<Secp256k1> for AffinePoint {
    fn decompress(x_bytes: &ElementBytes, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_bytes(x_bytes).and_then(|x| {
            let alpha = (x * &x * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                let y = FieldElement::conditional_select(
                    &beta.negate(1),
                    &beta,
                    // beta.is_odd() == y_is_odd
                    !(beta.normalize().is_odd() ^ y_is_odd),
                );

                Self {
                    x,
                    y: y.normalize(),
                }
            })
        })
    }
}

impl FromEncodedPoint<Secp256k1> for AffinePoint {
    /// Attempts to parse the given [`EncodedPoint`] as an SEC1-encoded [`AffinePoint`].
    ///
    /// # Returns
    ///
    /// `None` value if `encoded_point` is not on the secp256k1 curve.
    fn from_encoded_point(encoded_point: &EncodedPoint) -> CtOption<Self> {
        match encoded_point.tag() {
            sec1::Tag::CompressedEvenY => {
                AffinePoint::decompress(encoded_point.x(), Choice::from(0))
            }
            sec1::Tag::CompressedOddY => {
                AffinePoint::decompress(encoded_point.x(), Choice::from(1))
            }
            sec1::Tag::Uncompressed => {
                let x = FieldElement::from_bytes(encoded_point.x());
                let y = FieldElement::from_bytes(encoded_point.y().expect("missing y-coordinate"));

                x.and_then(|x| {
                    y.and_then(|y| {
                        // Check that the point is on the curve
                        let lhs = (y * &y).negate(1);
                        let rhs = x * &x * &x + &CURVE_EQUATION_B;
                        CtOption::new(AffinePoint { x, y }, (lhs + &rhs).normalizes_to_zero())
                    })
                })
            }
        }
    }
}

impl ToEncodedPoint<Secp256k1> for AffinePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        EncodedPoint::from_affine_coords(&self.x.to_bytes(), &self.y.to_bytes(), compress)
    }
}

impl From<AffinePoint> for EncodedPoint {
    /// Returns the SEC1 compressed encoding of this point.
    fn from(affine_point: AffinePoint) -> EncodedPoint {
        affine_point.to_encoded_point(true)
    }
}

impl Mul<NonZeroScalar> for AffinePoint {
    type Output = AffinePoint;

    fn mul(self, scalar: NonZeroScalar) -> Self {
        (ProjectivePoint::from(self) * scalar.as_ref())
            .to_affine()
            .unwrap()
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    fn neg(self) -> Self::Output {
        AffinePoint {
            x: self.x,
            y: self.y.negate(1).normalize_weak(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for AffinePoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

/// A point on the secp256k1 curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(p: AffinePoint) -> Self {
        ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::one(),
        }
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectivePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ProjectivePoint {
    /// Returns the additive identity of SECP256k1, also known as the "neutral element" or
    /// "point at infinity".
    pub const fn identity() -> ProjectivePoint {
        ProjectivePoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the base point of SECP256k1.
    pub fn generator() -> ProjectivePoint {
        AffinePoint::generator().into()
    }

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> CtOption<AffinePoint> {
        self.z.invert().map(|zinv| AffinePoint {
            x: self.x * &zinv,
            y: self.y * &zinv,
        })
    }

    /// Returns `-self`.
    fn neg(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y.negate(1).normalize_weak(),
            z: self.z,
        }
    }

    /// Returns `self + other`.
    fn add(&self, other: &ProjectivePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 7).

        let xx = self.x * &other.x;
        let yy = self.y * &other.y;
        let zz = self.z * &other.z;

        let n_xx_yy = (xx + &yy).negate(2);
        let n_yy_zz = (yy + &zz).negate(2);
        let n_xx_zz = (xx + &zz).negate(2);
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) + &n_xx_yy;
        let yz_pairs = ((self.y + &self.z) * &(other.y + &other.z)) + &n_yy_zz;
        let xz_pairs = ((self.x + &self.z) * &(other.x + &other.z)) + &n_xx_zz;

        let bzz = zz.mul_single(CURVE_EQUATION_B_SINGLE);
        let bzz3 = (bzz.double() + &bzz).normalize_weak();

        let yy_m_bzz3 = yy + &bzz3.negate(1);
        let yy_p_bzz3 = yy + &bzz3;

        let byz = &yz_pairs
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();
        let byz3 = (byz.double() + byz).normalize_weak();

        let xx3 = xx.double() + &xx;
        let bxx9 = (xx3.double() + &xx3)
            .normalize_weak()
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();

        let new_x = ((xy_pairs * &yy_m_bzz3) + &(byz3 * &xz_pairs).negate(1)).normalize_weak(); // m1
        let new_y = ((yy_p_bzz3 * &yy_m_bzz3) + &(bxx9 * &xz_pairs)).normalize_weak();
        let new_z = ((yz_pairs * &yy_p_bzz3) + &(xx3 * &xy_pairs)).normalize_weak();

        ProjectivePoint {
            x: new_x,
            y: new_y,
            z: new_z,
        }
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 8).

        let xx = self.x * &other.x;
        let yy = self.y * &other.y;
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) + &(xx + &yy).negate(2);
        let yz_pairs = (other.y * &self.z) + &self.y;
        let xz_pairs = (other.x * &self.z) + &self.x;

        let bzz = &self.z.mul_single(CURVE_EQUATION_B_SINGLE);
        let bzz3 = (bzz.double() + bzz).normalize_weak();

        let yy_m_bzz3 = yy + &bzz3.negate(1);
        let yy_p_bzz3 = yy + &bzz3;

        let byz = &yz_pairs
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();
        let byz3 = (byz.double() + byz).normalize_weak();

        let xx3 = xx.double() + &xx;
        let bxx9 = &(xx3.double() + &xx3)
            .normalize_weak()
            .mul_single(CURVE_EQUATION_B_SINGLE)
            .normalize_weak();

        ProjectivePoint {
            x: ((xy_pairs * &yy_m_bzz3) + &(byz3 * &xz_pairs).negate(1)).normalize_weak(),
            y: ((yy_p_bzz3 * &yy_m_bzz3) + &(bxx9 * &xz_pairs)).normalize_weak(),
            z: ((yz_pairs * &yy_p_bzz3) + &(xx3 * &xy_pairs)).normalize_weak(),
        }
    }

    /// Doubles this point.
    #[inline]
    pub fn double(&self) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 9).

        let yy = self.y.square();
        let zz = self.z.square();
        let xy2 = (self.x * &self.y).double();

        let bzz = &zz.mul_single(CURVE_EQUATION_B_SINGLE);
        let bzz3 = (bzz.double() + bzz).normalize_weak();
        let bzz9 = (bzz3.double() + &bzz3).normalize_weak();

        let yy_m_bzz9 = yy + &bzz9.negate(1);
        let yy_p_bzz3 = yy + &bzz3;

        let yy_zz = yy * &zz;
        let yy_zz8 = yy_zz.double().double().double();
        let t = (yy_zz8.double() + &yy_zz8)
            .normalize_weak()
            .mul_single(CURVE_EQUATION_B_SINGLE);

        ProjectivePoint {
            x: xy2 * &yy_m_bzz9,
            y: ((yy_m_bzz9 * &yy_p_bzz3) + &t).normalize_weak(),
            z: ((yy * &self.y) * &self.z)
                .double()
                .double()
                .double()
                .normalize_weak(),
        }
    }

    /// Returns `self - other`.
    fn sub(&self, other: &ProjectivePoint) -> ProjectivePoint {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        self.add_mixed(&other.neg())
    }

    /// Calculates SECP256k1 endomorphism: `self * lambda`.
    #[cfg(feature = "endomorphism-mul")]
    pub fn endomorphism(&self) -> Self {
        Self {
            x: self.x * &ENDOMORPHISM_BETA,
            y: self.y,
            z: self.z,
        }
    }
}

impl Default for ProjectivePoint {
    fn default() -> Self {
        Self::identity()
    }
}

impl Add<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(self, other)
    }
}

impl Add<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, other)
    }
}

impl AddAssign<ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl AddAssign<&ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl Add<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl Add<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl AddAssign<AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl Sub<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(self, other)
    }
}

impl Sub<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, other)
    }
}

impl SubAssign<ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl SubAssign<&ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl Sub<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl Sub<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl SubAssign<AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl Neg for ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(&self)
    }
}

impl<'a> Neg for &'a ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(self)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;

    use super::{AffinePoint, ProjectivePoint, Scalar, CURVE_EQUATION_B};
    use crate::{
        test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
        EncodedPoint,
    };
    use elliptic_curve::{
        point::Generator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        FromBytes,
    };

    const CURVE_EQUATION_B_BYTES: &str =
        "0000000000000000000000000000000000000000000000000000000000000007";

    const UNCOMPRESSED_BASEPOINT: &str =
        "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    const COMPRESSED_BASEPOINT: &str =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    #[test]
    fn verify_constants() {
        assert_eq!(
            hex::encode(CURVE_EQUATION_B.to_bytes()).to_uppercase(),
            CURVE_EQUATION_B_BYTES
        );
    }

    #[test]
    fn uncompressed_round_trip() {
        let pubkey =
            EncodedPoint::from_bytes(&hex::decode(UNCOMPRESSED_BASEPOINT).unwrap()).unwrap();
        let res: EncodedPoint = AffinePoint::from_encoded_point(&pubkey)
            .unwrap()
            .to_encoded_point(false)
            .into();

        assert_eq!(res, pubkey);
    }

    #[test]
    fn compressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(&hex::decode(COMPRESSED_BASEPOINT).unwrap()).unwrap();
        let res: EncodedPoint = AffinePoint::from_encoded_point(&pubkey)
            .unwrap()
            .to_encoded_point(true)
            .into();

        assert_eq!(res, pubkey);
    }

    #[test]
    fn uncompressed_to_compressed() {
        let encoded =
            EncodedPoint::from_bytes(&hex::decode(UNCOMPRESSED_BASEPOINT).unwrap()).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(true);

        assert_eq!(
            hex::encode(res.as_bytes()).to_uppercase(),
            COMPRESSED_BASEPOINT
        );
    }

    #[test]
    fn compressed_to_uncompressed() {
        let encoded =
            EncodedPoint::from_bytes(&hex::decode(COMPRESSED_BASEPOINT).unwrap()).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(false);

        assert_eq!(
            hex::encode(res.as_bytes()).to_uppercase(),
            UNCOMPRESSED_BASEPOINT
        );
    }

    #[test]
    fn affine_negation() {
        let basepoint = AffinePoint::generator();

        assert_eq!((-(-basepoint)), basepoint);
    }

    #[test]
    fn affine_to_projective() {
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

        assert_eq!(
            ProjectivePoint::from(basepoint_affine),
            basepoint_projective,
        );
        assert_eq!(basepoint_projective.to_affine().unwrap(), basepoint_affine);

        // The projective identity does not have an affine representation.
        assert!(bool::from(
            ProjectivePoint::identity().to_affine().is_none()
        ));
    }

    #[test]
    fn projective_identity_addition() {
        let identity = ProjectivePoint::identity();
        let generator = ProjectivePoint::generator();

        assert_eq!(identity + &generator, generator);
        assert_eq!(generator + &identity, generator);
    }

    #[test]
    fn projective_mixed_addition() {
        let identity = ProjectivePoint::identity();
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

        assert_eq!(identity + &basepoint_affine, basepoint_projective);
        assert_eq!(
            basepoint_projective + &basepoint_affine,
            basepoint_projective + &basepoint_projective
        );
    }

    #[test]
    fn test_vector_repeated_add() {
        let generator = ProjectivePoint::generator();
        let mut p = generator;

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(affine.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(affine.y.to_bytes()).to_uppercase().as_str(),
                ),
                ADD_TEST_VECTORS[i]
            );

            p = p + &generator;
        }
    }

    #[test]
    fn test_vector_repeated_add_mixed() {
        let generator = AffinePoint::generator();
        let mut p = ProjectivePoint::generator();

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(affine.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(affine.y.to_bytes()).to_uppercase().as_str(),
                ),
                ADD_TEST_VECTORS[i]
            );

            p = p + &generator;
        }
    }

    #[test]
    fn test_vector_double_generator() {
        let generator = ProjectivePoint::generator();
        let mut p = generator;

        for i in 0..2 {
            let affine = p.to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(affine.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(affine.y.to_bytes()).to_uppercase().as_str(),
                ),
                ADD_TEST_VECTORS[i]
            );

            p = p.double();
        }
    }

    #[test]
    fn projective_add_vs_double() {
        let generator = ProjectivePoint::generator();

        let r1 = generator + &generator;
        let r2 = generator.double();
        assert_eq!(r1, r2);

        let r1 = (generator + &generator) + &(generator + &generator);
        let r2 = generator.double().double();
        assert_eq!(r1, r2);
    }

    #[test]
    fn projective_add_and_sub() {
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

        assert_eq!(
            (basepoint_projective + &basepoint_projective) - &basepoint_projective,
            basepoint_projective
        );
        assert_eq!(
            (basepoint_projective + &basepoint_affine) - &basepoint_affine,
            basepoint_projective
        );
    }

    #[test]
    fn projective_double_and_sub() {
        let generator = ProjectivePoint::generator();

        assert_eq!(generator.double() - &generator, generator);
    }

    #[test]
    fn test_vector_scalar_mult() {
        let generator = ProjectivePoint::generator();

        for (k, coords) in ADD_TEST_VECTORS
            .iter()
            .enumerate()
            .map(|(k, coords)| (Scalar::from(k as u32 + 1), *coords))
            .chain(MUL_TEST_VECTORS.iter().cloned().map(|(k, x, y)| {
                (
                    Scalar::from_bytes(hex::decode(k).unwrap()[..].try_into().unwrap()).unwrap(),
                    (x, y),
                )
            }))
        {
            let res = (generator * &k).to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(res.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(res.y.to_bytes()).to_uppercase().as_str(),
                ),
                coords,
            );
        }
    }

    #[cfg(feature = "rand")]
    #[test]
    fn generate_secret_key() {
        use crate::SecretKey;
        use elliptic_curve::{rand_core::OsRng, Generate};

        let key = SecretKey::generate(&mut OsRng);

        // Sanity check
        assert!(!key.as_bytes().iter().all(|b| *b == 0))
    }
}
