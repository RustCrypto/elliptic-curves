//! Projective points

#![allow(clippy::op_ref)]

use super::{AffinePoint, FieldElement, Scalar, CURVE_EQUATION_B};
use crate::{CompressedPoint, EncodedPoint, NistP256};
use core::{
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::Limb,
    group::{
        ff::Field,
        prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup},
        Curve, Group, GroupEncoding,
    },
    ops::LinearCombination,
    rand_core::RngCore,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    PrimeCurveArithmetic, ProjectiveArithmetic,
};

impl ProjectiveArithmetic for NistP256 {
    type ProjectivePoint = ProjectivePoint;
}

impl PrimeCurveArithmetic for NistP256 {
    type CurveGroup = ProjectivePoint;
}

/// A point on the secp256r1 curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl ProjectivePoint {
    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Base point of P-256.
    pub const GENERATOR: Self = Self {
        x: AffinePoint::GENERATOR.x,
        y: AffinePoint::GENERATOR.y,
        z: FieldElement::ONE,
    };

    /// Returns the additive identity of P-256, also known as the "neutral element" or
    /// "point at infinity".
    #[deprecated(since = "0.10.1", note = "use `ProjectivePoint::IDENTITY` instead")]
    pub const fn identity() -> ProjectivePoint {
        Self::IDENTITY
    }

    /// Returns the base point of P-256.
    #[deprecated(since = "0.10.1", note = "use `ProjectivePoint::GENERATOR` instead")]
    pub fn generator() -> ProjectivePoint {
        Self::GENERATOR
    }

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> AffinePoint {
        self.z
            .invert()
            .map(|zinv| AffinePoint {
                x: self.x * &zinv,
                y: self.y * &zinv,
                infinity: 0,
            })
            .unwrap_or(AffinePoint::IDENTITY)
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

        let mut ret = ProjectivePoint {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 28, 32, 33
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 29, 30, 31
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 34, 35, 36
        };
        ret.conditional_assign(self, other.is_identity());
        ret
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
        let mut ret = ProjectivePoint::IDENTITY;

        for limb in k.limbs().iter().rev() {
            for i in (0..Limb::BIT_SIZE).rev() {
                ret = ret.double();
                ret.conditional_assign(&(ret + self), Choice::from(((limb.0 >> i) & 1) as u8));
            }
        }

        ret
    }
}

impl Group for ProjectivePoint {
    type Scalar = Scalar;

    fn random(mut rng: impl RngCore) -> Self {
        Self::GENERATOR * Scalar::random(&mut rng)
    }

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::IDENTITY)
    }

    #[must_use]
    fn double(&self) -> Self {
        ProjectivePoint::double(self)
    }
}

impl GroupEncoding for ProjectivePoint {
    type Repr = CompressedPoint;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint as GroupEncoding>::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_affine().to_bytes()
    }
}

impl PrimeGroup for ProjectivePoint {}

impl Curve for ProjectivePoint {
    type AffineRepr = AffinePoint;

    fn to_affine(&self) -> AffinePoint {
        ProjectivePoint::to_affine(self)
    }
}

impl PrimeCurve for ProjectivePoint {
    type Affine = AffinePoint;
}

impl LinearCombination for ProjectivePoint {}

impl From<AffinePoint> for ProjectivePoint {
    fn from(p: AffinePoint) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl From<&AffinePoint> for ProjectivePoint {
    fn from(p: &AffinePoint) -> Self {
        Self::from(*p)
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(p: ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl From<&ProjectivePoint> for AffinePoint {
    fn from(p: &ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl FromEncodedPoint<NistP256> for ProjectivePoint {
    fn from_encoded_point(p: &EncodedPoint) -> CtOption<Self> {
        AffinePoint::from_encoded_point(p).map(ProjectivePoint::from)
    }
}

impl ToEncodedPoint<NistP256> for ProjectivePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.to_affine().to_encoded_point(compress)
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

impl DefaultIsZeroes for ProjectivePoint {}

impl Eq for ProjectivePoint {}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Default for ProjectivePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Add<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, &other)
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

impl Add<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, &other)
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

impl AddAssign<&AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, rhs);
    }
}

impl Sum for ProjectivePoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}

impl<'a> Sum<&'a ProjectivePoint> for ProjectivePoint {
    fn sum<I: Iterator<Item = &'a ProjectivePoint>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl Sub<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, &other)
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

impl Sub<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, &other)
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

impl SubAssign<&AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, rhs);
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: Scalar) -> ProjectivePoint {
        ProjectivePoint::mul(&self, &other)
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
    use super::{AffinePoint, ProjectivePoint, Scalar};
    use crate::test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS};
    use elliptic_curve::group::{ff::PrimeField, prime::PrimeCurveAffine, GroupEncoding};

    #[test]
    fn affine_to_projective() {
        let basepoint_affine = AffinePoint::GENERATOR;
        let basepoint_projective = ProjectivePoint::GENERATOR;

        assert_eq!(
            ProjectivePoint::from(basepoint_affine),
            basepoint_projective,
        );
        assert_eq!(basepoint_projective.to_affine(), basepoint_affine);
        assert!(!bool::from(basepoint_projective.to_affine().is_identity()));

        assert!(bool::from(
            ProjectivePoint::IDENTITY.to_affine().is_identity()
        ));
    }

    #[test]
    fn projective_identity_addition() {
        let identity = ProjectivePoint::IDENTITY;
        let generator = ProjectivePoint::GENERATOR;

        assert_eq!(identity + &generator, generator);
        assert_eq!(generator + &identity, generator);
    }

    #[test]
    fn projective_mixed_addition() {
        let identity = ProjectivePoint::IDENTITY;
        let basepoint_affine = AffinePoint::GENERATOR;
        let basepoint_projective = ProjectivePoint::GENERATOR;

        assert_eq!(identity + &basepoint_affine, basepoint_projective);
        assert_eq!(
            basepoint_projective + &basepoint_affine,
            basepoint_projective + &basepoint_projective
        );
    }

    #[test]
    fn test_vector_repeated_add() {
        let generator = ProjectivePoint::GENERATOR;
        let mut p = generator;

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p += &generator;
        }
    }

    #[test]
    fn test_vector_repeated_add_mixed() {
        let generator = AffinePoint::GENERATOR;
        let mut p = ProjectivePoint::GENERATOR;

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p += &generator;
        }
    }

    #[test]
    fn test_vector_add_mixed_identity() {
        let generator = ProjectivePoint::GENERATOR;
        let p0 = generator + ProjectivePoint::IDENTITY;
        let p1 = generator + AffinePoint::IDENTITY;
        assert_eq!(p0, p1);
    }

    #[test]
    fn test_vector_double_generator() {
        let generator = ProjectivePoint::GENERATOR;
        let mut p = generator;

        for i in 0..2 {
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p = p.double();
        }
    }

    #[test]
    fn projective_add_vs_double() {
        let generator = ProjectivePoint::GENERATOR;
        assert_eq!(generator + &generator, generator.double());
    }

    #[test]
    fn projective_add_and_sub() {
        let basepoint_affine = AffinePoint::GENERATOR;
        let basepoint_projective = ProjectivePoint::GENERATOR;

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
        let generator = ProjectivePoint::GENERATOR;
        assert_eq!(generator.double() - &generator, generator);
    }

    #[test]
    fn test_vector_scalar_mult() {
        let generator = ProjectivePoint::GENERATOR;

        for (k, coords) in ADD_TEST_VECTORS
            .iter()
            .enumerate()
            .map(|(k, coords)| (Scalar::from(k as u64 + 1), *coords))
            .chain(
                MUL_TEST_VECTORS
                    .iter()
                    .cloned()
                    .map(|(k, x, y)| (Scalar::from_repr(k.into()).unwrap(), (x, y))),
            )
        {
            let res = (generator * &k).to_affine();
            assert_eq!(res.x.to_bytes(), coords.0.into());
            assert_eq!(res.y.to_bytes(), coords.1.into());
        }
    }

    #[test]
    fn projective_identity_to_bytes() {
        // This is technically an invalid SEC1 encoding, but is preferable to panicking.
        assert_eq!([0; 33], ProjectivePoint::IDENTITY.to_bytes().as_slice());
    }
}
