//! A pure-Rust implementation of group operations on secp256r1.

mod field;
pub(crate) mod scalar;
mod util;

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    generic_array::arr,
    point::Generator,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    weierstrass::point::Decompress,
    Arithmetic,
};

use crate::{ElementBytes, EncodedPoint, NistP256};
use field::{FieldElement, MODULUS};
use scalar::{NonZeroScalar, Scalar};

#[cfg(feature = "zeroize")]
use elliptic_curve::zeroize::Zeroize;

/// a = -3
const CURVE_EQUATION_A: FieldElement = FieldElement::zero()
    .subtract(&FieldElement::one())
    .subtract(&FieldElement::one())
    .subtract(&FieldElement::one());

/// b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
const CURVE_EQUATION_B: FieldElement = FieldElement([
    0xd89c_df62_29c4_bddf,
    0xacf0_05cd_7884_3090,
    0xe5a2_20ab_f721_2ed6,
    0xdc30_061d_0487_4834,
]);

impl Arithmetic for NistP256 {
    type Scalar = Scalar;
    type AffinePoint = AffinePoint;
}

/// A point on the secp256r1 curve in affine coordinates.
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
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl Generator for AffinePoint {
    /// Returns the base point of P-256.
    fn generator() -> AffinePoint {
        // NIST P-256 basepoint in affine coordinates:
        // x = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
        // y = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
        AffinePoint {
            x: FieldElement::from_bytes(&arr![u8;
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96
            ])
            .unwrap(),
            y: FieldElement::from_bytes(&arr![u8;
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5
            ])
            .unwrap(),
        }
    }
}

impl Decompress<NistP256> for AffinePoint {
    fn decompress(x_bytes: &ElementBytes, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_bytes(x_bytes).and_then(|x| {
            let alpha = x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                let y = FieldElement::conditional_select(
                    &(MODULUS - &beta),
                    &beta,
                    // beta.is_odd() == y_is_odd
                    !(beta.is_odd() ^ y_is_odd),
                );

                Self { x, y }
            })
        })
    }
}

impl FromEncodedPoint<NistP256> for AffinePoint {
    /// Attempts to parse the given [`EncodedPoint`] as an SEC1-encoded [`AffinePoint`].
    ///
    /// # Returns
    ///
    /// `None` value if `encoded_point` is not on the secp256r1 curve.
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
                        let lhs = y * &y;
                        let rhs = x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B;
                        CtOption::new(AffinePoint { x, y }, lhs.ct_eq(&rhs))
                    })
                })
            }
        }
    }
}

impl ToEncodedPoint<NistP256> for AffinePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        EncodedPoint::from_affine_coords(&self.x.to_bytes(), &self.y.to_bytes(), compress)
    }
}

impl From<AffinePoint> for EncodedPoint {
    /// Returns the SEC1 compressed encoding of this point.
    fn from(affine_point: AffinePoint) -> EncodedPoint {
        affine_point.to_encoded_point(false)
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
            y: -self.y,
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

/// A point on the secp256r1 curve in projective coordinates.
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
    /// Returns the additive identity of P-256, also known as the "neutral element" or
    /// "point at infinity".
    pub const fn identity() -> ProjectivePoint {
        ProjectivePoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the base point of P-256.
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
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Returns `self + other`.
    fn add(&self, other: &ProjectivePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 4). The comments after each line
        // indicate which algorithm steps are being performed.

        let xx = self.x * &other.x; // 1
        let yy = self.y * &other.y; // 2
        let zz = self.z * &other.z; // 3
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy); // 4, 5, 6, 7, 8
        let yz_pairs = ((self.y + &self.z) * &(other.y + &other.z)) - &(yy + &zz); // 9, 10, 11, 12, 13
        let xz_pairs = ((self.x + &self.z) * &(other.x + &other.z)) - &(xx + &zz); // 14, 15, 16, 17, 18

        let bzz_part = xz_pairs - &(CURVE_EQUATION_B * &zz); // 19, 20
        let bzz3_part = bzz_part.double() + &bzz_part; // 21, 22
        let yy_m_bzz3 = yy - &bzz3_part; // 23
        let yy_p_bzz3 = yy + &bzz3_part; // 24

        let zz3 = zz.double() + &zz; // 26, 27
        let bxz_part = (CURVE_EQUATION_B * &xz_pairs) - &(zz3 + &xx); // 25, 28, 29
        let bxz3_part = bxz_part.double() + &bxz_part; // 30, 31
        let xx3_m_zz3 = xx.double() + &xx - &zz3; // 32, 33, 34

        ProjectivePoint {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 35, 39, 40
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 36, 37, 38
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 41, 42, 43
        }
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        // We implement the complete mixed addition formula from Renes-Costello-Batina
        // 2015 (Algorithm 5). The comments after each line indicate which algorithm steps
        // are being performed.

        let xx = self.x * &other.x; // 1
        let yy = self.y * &other.y; // 2
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy); // 3, 4, 5, 6, 7
        let yz_pairs = (other.y * &self.z) + &self.y; // 8, 9 (t4)
        let xz_pairs = (other.x * &self.z) + &self.x; // 10, 11 (y3)

        let bz_part = xz_pairs - &(CURVE_EQUATION_B * &self.z); // 12, 13
        let bz3_part = bz_part.double() + &bz_part; // 14, 15
        let yy_m_bzz3 = yy - &bz3_part; // 16
        let yy_p_bzz3 = yy + &bz3_part; // 17

        let z3 = self.z.double() + &self.z; // 19, 20
        let bxz_part = (CURVE_EQUATION_B * &xz_pairs) - &(z3 + &xx); // 18, 21, 22
        let bxz3_part = bxz_part.double() + &bxz_part; // 23, 24
        let xx3_m_zz3 = xx.double() + &xx - &z3; // 25, 26, 27

        ProjectivePoint {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 28, 32, 33
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 29, 30, 31
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 34, 35, 36
        }
    }

    /// Doubles this point.
    pub fn double(&self) -> ProjectivePoint {
        // We implement the exception-free point doubling formula from
        // Renes-Costello-Batina 2015 (Algorithm 6). The comments after each line
        // indicate which algorithm steps are being performed.

        let xx = self.x.square(); // 1
        let yy = self.y.square(); // 2
        let zz = self.z.square(); // 3
        let xy2 = (self.x * &self.y).double(); // 4, 5
        let xz2 = (self.x * &self.z).double(); // 6, 7

        let bzz_part = (CURVE_EQUATION_B * &zz) - &xz2; // 8, 9
        let bzz3_part = bzz_part.double() + &bzz_part; // 10, 11
        let yy_m_bzz3 = yy - &bzz3_part; // 12
        let yy_p_bzz3 = yy + &bzz3_part; // 13
        let y_frag = yy_p_bzz3 * &yy_m_bzz3; // 14
        let x_frag = yy_m_bzz3 * &xy2; // 15

        let zz3 = zz.double() + &zz; // 16, 17
        let bxz2_part = (CURVE_EQUATION_B * &xz2) - &(zz3 + &xx); // 18, 19, 20
        let bxz6_part = bxz2_part.double() + &bxz2_part; // 21, 22
        let xx3_m_zz3 = xx.double() + &xx - &zz3; // 23, 24, 25

        let y = y_frag + &(xx3_m_zz3 * &bxz6_part); // 26, 27
        let yz2 = (self.y * &self.z).double(); // 28, 29
        let x = x_frag - &(bxz6_part * &yz2); // 30, 31
        let z = (yz2 * &yy).double().double(); // 32, 33, 34

        ProjectivePoint { x, y, z }
    }

    /// Returns `self - other`.
    fn sub(&self, other: &ProjectivePoint) -> ProjectivePoint {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        self.add_mixed(&other.neg())
    }

    /// Returns `[k] self`.
    fn mul(&self, k: &Scalar) -> ProjectivePoint {
        let mut ret = ProjectivePoint::identity();

        for limb in k.0.iter().rev() {
            for i in (0..64).rev() {
                ret = ret.double();
                ret.conditional_assign(&(ret + self), Choice::from(((limb >> i) & 1u64) as u8));
            }
        }

        ret
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

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        ProjectivePoint::mul(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        ProjectivePoint::mul(&self, other)
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = ProjectivePoint::mul(self, &rhs);
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = ProjectivePoint::mul(self, rhs);
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

    use super::{AffinePoint, ProjectivePoint, Scalar, CURVE_EQUATION_A, CURVE_EQUATION_B};
    use crate::{
        test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
        EncodedPoint,
    };
    use elliptic_curve::{
        point::Generator,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        FromBytes,
    };

    const CURVE_EQUATION_A_BYTES: &str =
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
    const CURVE_EQUATION_B_BYTES: &str =
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";

    const UNCOMPRESSED_BASEPOINT: &str =
        "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    const COMPRESSED_BASEPOINT: &str =
        "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";

    #[test]
    fn verify_constants() {
        assert_eq!(
            hex::encode(CURVE_EQUATION_A.to_bytes()).to_uppercase(),
            CURVE_EQUATION_A_BYTES
        );
        assert_eq!(
            hex::encode(CURVE_EQUATION_B.to_bytes()).to_uppercase(),
            CURVE_EQUATION_B_BYTES
        );
    }

    #[test]
    fn uncompressed_round_trip() {
        let pubkey =
            EncodedPoint::from_bytes(&hex::decode(UNCOMPRESSED_BASEPOINT).unwrap()).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.into();
        assert_eq!(res, pubkey);
    }

    #[test]
    fn compressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(&hex::decode(COMPRESSED_BASEPOINT).unwrap()).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.to_encoded_point(true).into();
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

        assert_eq!(-(-basepoint), basepoint);
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

        assert_eq!(generator + &generator, generator.double());
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
            .map(|(k, coords)| (Scalar::from(k as u64 + 1), *coords))
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
