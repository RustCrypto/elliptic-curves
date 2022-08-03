//! Projective curve points.

#![allow(clippy::needless_range_loop, clippy::op_ref)]

use crate::{AffinePoint, Field, WeierstrassCurve};
use core::{
    borrow::Borrow,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::{ArrayEncoding, Encoding},
    generic_array::ArrayLength,
    group::{
        self,
        cofactor::CofactorGroup,
        prime::{PrimeCurve, PrimeGroup},
        Group, GroupEncoding,
    },
    ops::LinearCombination,
    rand_core::RngCore,
    sec1::{CompressedPoint, ModulusSize, UncompressedPointSize},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Error, FieldBytes, FieldSize, PublicKey, Result, Scalar,
};

/// Point on a Weierstrass curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint<C: WeierstrassCurve> {
    x: C::FieldElement,
    y: C::FieldElement,
    z: C::FieldElement,
}

impl<C> ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    /// Additive identity of the group a.k.a. the point at infinity.
    pub const IDENTITY: Self = Self {
        x: C::ZERO,
        y: C::ONE,
        z: C::ZERO,
    };

    /// Base point of the curve.
    pub const GENERATOR: Self = Self {
        x: C::GENERATOR.0,
        y: C::GENERATOR.1,
        z: C::ONE,
    };

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> AffinePoint<C> {
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
    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }

    /// Returns `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 4). The comments after each line
        // indicate which algorithm steps are being performed.

        let xx = self.x * &other.x; // 1
        let yy = self.y * &other.y; // 2
        let zz = self.z * &other.z; // 3
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy); // 4, 5, 6, 7, 8
        let yz_pairs = ((self.y + &self.z) * &(other.y + &other.z)) - &(yy + &zz); // 9, 10, 11, 12, 13
        let xz_pairs = ((self.x + &self.z) * &(other.x + &other.z)) - &(xx + &zz); // 14, 15, 16, 17, 18

        let bzz_part = xz_pairs - &(C::EQUATION_B * &zz); // 19, 20
        let bzz3_part = bzz_part.double() + &bzz_part; // 21, 22
        let yy_m_bzz3 = yy - &bzz3_part; // 23
        let yy_p_bzz3 = yy + &bzz3_part; // 24

        let zz3 = zz.double() + &zz; // 26, 27
        let bxz_part = (C::EQUATION_B * &xz_pairs) - &(zz3 + &xx); // 25, 28, 29
        let bxz3_part = bxz_part.double() + &bxz_part; // 30, 31
        let xx3_m_zz3 = xx.double() + &xx - &zz3; // 32, 33, 34

        Self {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 35, 39, 40
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 36, 37, 38
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 41, 42, 43
        }
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint<C>) -> Self {
        // We implement the complete mixed addition formula from Renes-Costello-Batina
        // 2015 (Algorithm 5). The comments after each line indicate which algorithm
        // steps are being performed.

        let xx = self.x * &other.x; // 1
        let yy = self.y * &other.y; // 2
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy); // 3, 4, 5, 6, 7
        let yz_pairs = (other.y * &self.z) + &self.y; // 8, 9 (t4)
        let xz_pairs = (other.x * &self.z) + &self.x; // 10, 11 (y3)

        let bz_part = xz_pairs - &(C::EQUATION_B * &self.z); // 12, 13
        let bz3_part = bz_part.double() + &bz_part; // 14, 15
        let yy_m_bzz3 = yy - &bz3_part; // 16
        let yy_p_bzz3 = yy + &bz3_part; // 17

        let z3 = self.z.double() + &self.z; // 19, 20
        let bxz_part = (C::EQUATION_B * &xz_pairs) - &(z3 + &xx); // 18, 21, 22
        let bxz3_part = bxz_part.double() + &bxz_part; // 23, 24
        let xx3_m_zz3 = xx.double() + &xx - &z3; // 25, 26, 27

        let mut ret = Self {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 28, 32, 33
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 29, 30, 31
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 34, 35, 36
        };
        ret.conditional_assign(self, other.is_identity());
        ret
    }

    /// Doubles this point.
    pub fn double(&self) -> Self {
        // We implement the exception-free point doubling formula from
        // Renes-Costello-Batina 2015 (Algorithm 6). The comments after each line
        // indicate which algorithm steps are being performed.

        let xx = self.x.square(); // 1
        let yy = self.y.square(); // 2
        let zz = self.z.square(); // 3
        let xy2 = (self.x * &self.y).double(); // 4, 5
        let xz2 = (self.x * &self.z).double(); // 6, 7

        let bzz_part = (C::EQUATION_B * &zz) - &xz2; // 8, 9
        let bzz3_part = bzz_part.double() + &bzz_part; // 10, 11
        let yy_m_bzz3 = yy - &bzz3_part; // 12
        let yy_p_bzz3 = yy + &bzz3_part; // 13
        let y_frag = yy_p_bzz3 * &yy_m_bzz3; // 14
        let x_frag = yy_m_bzz3 * &xy2; // 15

        let zz3 = zz.double() + &zz; // 16, 17
        let bxz2_part = (C::EQUATION_B * &xz2) - &(zz3 + &xx); // 18, 19, 20
        let bxz6_part = bxz2_part.double() + &bxz2_part; // 21, 22
        let xx3_m_zz3 = xx.double() + &xx - &zz3; // 23, 24, 25

        let y = y_frag + &(xx3_m_zz3 * &bxz6_part); // 26, 27
        let yz2 = (self.y * &self.z).double(); // 28, 29
        let x = x_frag - &(bxz6_part * &yz2); // 30, 31
        let z = (yz2 * &yy).double().double(); // 32, 33, 34

        Self { x, y, z }
    }

    /// Returns `self - other`.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint<C>) -> Self {
        self.add_mixed(&other.neg())
    }

    /// Returns `[k] self`.
    fn mul(&self, k: &Scalar<C>) -> Self {
        let k = Into::<C::UInt>::into(*k).to_le_byte_array();

        let mut pc = [Self::default(); 16];
        pc[0] = Self::IDENTITY;
        pc[1] = *self;

        for i in 2..16 {
            pc[i] = if i % 2 == 0 {
                pc[i / 2].double()
            } else {
                pc[i - 1].add(self)
            };
        }

        let mut q = Self::IDENTITY;
        let mut pos = C::UInt::BIT_SIZE - 4;

        loop {
            let slot = (k[(pos >> 3) as usize] >> (pos & 7)) & 0xf;

            let mut t = ProjectivePoint::IDENTITY;

            for i in 1..16 {
                t.conditional_assign(
                    &pc[i],
                    Choice::from(((slot as usize ^ i).wrapping_sub(1) >> 8) as u8 & 1),
                );
            }

            q = q.add(&t);

            if pos == 0 {
                break;
            }

            q = q.double().double().double().double();
            pos -= 4;
        }

        q
    }
}

impl<C> CofactorGroup for ProjectivePoint<C>
where
    C: WeierstrassCurve,
    FieldBytes<C>: Copy,
    FieldSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    type Subgroup = Self;

    fn clear_cofactor(&self) -> Self::Subgroup {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self> {
        CtOption::new(self, 1.into())
    }

    fn is_torsion_free(&self) -> Choice {
        1.into()
    }
}

impl<C> ConditionallySelectable for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: C::FieldElement::conditional_select(&a.x, &b.x, choice),
            y: C::FieldElement::conditional_select(&a.y, &b.y, choice),
            z: C::FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl<C> ConstantTimeEq for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl<C> Default for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl<C> DefaultIsZeroes for ProjectivePoint<C> where C: WeierstrassCurve {}

impl<C> Eq for ProjectivePoint<C> where C: WeierstrassCurve {}

impl<C> From<AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn from(p: AffinePoint<C>) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: C::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl<C> From<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn from(p: &AffinePoint<C>) -> Self {
        Self::from(*p)
    }
}

impl<C> From<PublicKey<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn from(public_key: PublicKey<C>) -> ProjectivePoint<C> {
        AffinePoint::from(public_key).into()
    }
}

impl<C> From<&PublicKey<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn from(public_key: &PublicKey<C>) -> ProjectivePoint<C> {
        AffinePoint::<C>::from(public_key).into()
    }
}

impl<C> Group for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Scalar = Scalar<C>;

    fn random(mut rng: impl RngCore) -> Self {
        Self::GENERATOR * <Scalar<C> as Field>::random(&mut rng)
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

impl<C> GroupEncoding for ProjectivePoint<C>
where
    C: WeierstrassCurve,
    FieldBytes<C>: Copy,
    FieldSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    type Repr = CompressedPoint<C>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint<C> as GroupEncoding>::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_affine().to_bytes()
    }
}

impl<C> group::Curve for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type AffineRepr = AffinePoint<C>;

    fn to_affine(&self) -> AffinePoint<C> {
        ProjectivePoint::to_affine(self)
    }
}

impl<C> LinearCombination for ProjectivePoint<C> where C: WeierstrassCurve {}

impl<C> PrimeGroup for ProjectivePoint<C>
where
    C: WeierstrassCurve,
    FieldBytes<C>: Copy,
    FieldSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C> PrimeCurve for ProjectivePoint<C>
where
    C: WeierstrassCurve,
    FieldBytes<C>: Copy,
    FieldSize<C>: ModulusSize,
    CompressedPoint<C>: Copy,
    <UncompressedPointSize<C> as ArrayLength<u8>>::ArrayType: Copy,
{
    type Affine = AffinePoint<C>;
}

impl<C> PartialEq for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> TryFrom<ProjectivePoint<C>> for PublicKey<C>
where
    C: WeierstrassCurve,
{
    type Error = Error;

    fn try_from(point: ProjectivePoint<C>) -> Result<PublicKey<C>> {
        AffinePoint::<C>::from(point).try_into()
    }
}

impl<C> TryFrom<&ProjectivePoint<C>> for PublicKey<C>
where
    C: WeierstrassCurve,
{
    type Error = Error;

    fn try_from(point: &ProjectivePoint<C>) -> Result<PublicKey<C>> {
        AffinePoint::<C>::from(point).try_into()
    }
}

//
// Arithmetic trait impls
//

impl<C> Add<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(&self, &other)
    }
}

impl<C> Add<&ProjectivePoint<C>> for &ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(self, other)
    }
}

impl<C> Add<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(&self, other)
    }
}

impl<C> AddAssign<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn add_assign(&mut self, rhs: ProjectivePoint<C>) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl<C> AddAssign<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn add_assign(&mut self, rhs: &ProjectivePoint<C>) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl<C> Add<AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(&self, &other)
    }
}

impl<C> Add<&AffinePoint<C>> for &ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl<C> Add<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl<C> AddAssign<AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn add_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl<C> AddAssign<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn add_assign(&mut self, rhs: &AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, rhs);
    }
}

impl<C> Sum for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}

impl<'a, C> Sum<&'a ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn sum<I: Iterator<Item = &'a ProjectivePoint<C>>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<C> Sub<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(&self, &other)
    }
}

impl<C> Sub<&ProjectivePoint<C>> for &ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(self, other)
    }
}

impl<C> Sub<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(&self, other)
    }
}

impl<C> SubAssign<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn sub_assign(&mut self, rhs: ProjectivePoint<C>) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl<C> SubAssign<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn sub_assign(&mut self, rhs: &ProjectivePoint<C>) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl<C> Sub<AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(&self, &other)
    }
}

impl<C> Sub<&AffinePoint<C>> for &ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl<C> Sub<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl<C> SubAssign<AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn sub_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl<C> SubAssign<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    fn sub_assign(&mut self, rhs: &AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, rhs);
    }
}

impl<C, S> Mul<S> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
    S: Borrow<Scalar<C>>,
{
    type Output = Self;

    fn mul(self, scalar: S) -> Self {
        ProjectivePoint::mul(&self, scalar.borrow())
    }
}

impl<C> Mul<&Scalar<C>> for &ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn mul(self, scalar: &Scalar<C>) -> ProjectivePoint<C> {
        ProjectivePoint::mul(self, scalar)
    }
}

impl<C, S> MulAssign<S> for ProjectivePoint<C>
where
    C: WeierstrassCurve,
    S: Borrow<Scalar<C>>,
{
    fn mul_assign(&mut self, scalar: S) {
        *self = ProjectivePoint::mul(self, scalar.borrow());
    }
}

impl<C> Neg for ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn neg(self) -> ProjectivePoint<C> {
        ProjectivePoint::neg(&self)
    }
}

impl<'a, C> Neg for &'a ProjectivePoint<C>
where
    C: WeierstrassCurve,
{
    type Output = ProjectivePoint<C>;

    fn neg(self) -> ProjectivePoint<C> {
        ProjectivePoint::neg(self)
    }
}
