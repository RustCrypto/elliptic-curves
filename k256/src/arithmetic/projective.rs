//! Projective points

use super::{AffinePoint, FieldElement, Scalar, CURVE_EQUATION_B_SINGLE};
use crate::{CompressedPoint, EncodedPoint, Secp256k1};
use core::{
    iter::Sum,
    ops::{Add, AddAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    group::{
        ff::Field,
        prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup},
        Curve, Group, GroupEncoding,
    },
    rand_core::RngCore,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    ProjectiveArithmetic,
};

#[rustfmt::skip]
const ENDOMORPHISM_BETA: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10,
    0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
    0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95,
    0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
]);

impl ProjectiveArithmetic for Secp256k1 {
    type ProjectivePoint = ProjectivePoint;
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
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::one(),
        };
        Self::conditional_select(&projective, &Self::identity(), p.infinity)
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(p: ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl FromEncodedPoint<Secp256k1> for ProjectivePoint {
    fn from_encoded_point(p: &EncodedPoint) -> Option<Self> {
        AffinePoint::from_encoded_point(p).map(ProjectivePoint::from)
    }
}

impl ToEncodedPoint<Secp256k1> for ProjectivePoint {
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

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ProjectivePoint {}

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
    pub fn to_affine(&self) -> AffinePoint {
        self.z
            .invert()
            .map(|zinv| AffinePoint {
                x: self.x * &zinv,
                y: self.y * &zinv,
                infinity: Choice::from(0),
            })
            .unwrap_or_else(AffinePoint::identity)
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

        let mut ret = ProjectivePoint {
            x: ((xy_pairs * &yy_m_bzz3) + &(byz3 * &xz_pairs).negate(1)).normalize_weak(),
            y: ((yy_p_bzz3 * &yy_m_bzz3) + &(bxx9 * &xz_pairs)).normalize_weak(),
            z: ((yz_pairs * &yy_p_bzz3) + &(xx3 * &xy_pairs)).normalize_weak(),
        };
        ret.conditional_assign(self, other.is_identity());
        ret
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
    pub fn endomorphism(&self) -> Self {
        Self {
            x: self.x * &ENDOMORPHISM_BETA,
            y: self.y,
            z: self.z,
        }
    }
}

impl Group for ProjectivePoint {
    type Scalar = Scalar;

    fn random(mut rng: impl RngCore) -> Self {
        Self::generator() * Scalar::random(&mut rng)
    }

    fn identity() -> Self {
        ProjectivePoint::identity()
    }

    fn generator() -> Self {
        ProjectivePoint::generator()
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::identity())
    }

    #[must_use]
    fn double(&self) -> Self {
        ProjectivePoint::double(self)
    }
}

impl GroupEncoding for ProjectivePoint {
    type Repr = CompressedPoint;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint as GroupEncoding>::from_bytes(bytes).map(|point| point.into())
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        CompressedPoint::clone_from_slice(self.to_affine().to_encoded_point(true).as_bytes())
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

impl Add<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, &other)
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
        iter.fold(ProjectivePoint::identity(), |a, b| a + b)
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
    use super::{AffinePoint, ProjectivePoint};
    use crate::{
        test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
        Scalar,
    };
    use elliptic_curve::group::{ff::PrimeField, prime::PrimeCurveAffine};

    #[test]
    fn affine_to_projective() {
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

        assert_eq!(
            ProjectivePoint::from(basepoint_affine),
            basepoint_projective,
        );
        assert_eq!(basepoint_projective.to_affine(), basepoint_affine);
        assert!(!bool::from(basepoint_projective.to_affine().is_identity()));

        assert!(bool::from(
            ProjectivePoint::identity().to_affine().is_identity()
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
            let affine = p.to_affine();

            let (expected_x, expected_y) = ADD_TEST_VECTORS[i];
            assert_eq!(affine.x.to_bytes(), expected_x.into());
            assert_eq!(affine.y.to_bytes(), expected_y.into());

            p += &generator;
        }
    }

    #[test]
    fn test_vector_repeated_add_mixed() {
        let generator = AffinePoint::generator();
        let mut p = ProjectivePoint::generator();

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
        let generator = ProjectivePoint::generator();
        let p0 = generator + ProjectivePoint::identity();
        let p1 = generator + AffinePoint::identity();
        assert_eq!(p0, p1);
    }

    #[test]
    fn test_vector_double_generator() {
        let generator = ProjectivePoint::generator();
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
}
