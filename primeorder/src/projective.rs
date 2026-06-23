//! Projective curve points.

#![allow(clippy::needless_range_loop, clippy::op_ref)]

use crate::{
    AffinePoint, Field, LookupTable, MulBackend, PrimeCurveParams, Radix16Decomposition,
    Radix16Digits, point_arithmetic::PointArithmetic,
};
use core::{array, borrow::Borrow, iter::Sum, iter::zip};
use elliptic_curve::{
    BatchNormalize, CurveGroup, Error, Generate, PublicKey, Result, Scalar,
    array::typenum::Unsigned,
    ctutils,
    group::{
        Group, GroupEncoding,
        cofactor::CofactorGroup,
        prime::{PrimeCurve, PrimeGroup},
    },
    ops::{
        Add, AddAssign, BatchInvert, LinearCombination, Mul, MulAssign, MulByGeneratorVartime,
        MulVartime, Neg, Sub, SubAssign,
    },
    point::{Double, NonIdentity},
    rand_core::{TryCryptoRng, TryRng},
    sec1::{CompressedPoint, FromSec1Point, Sec1Point, ToSec1Point},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "serde")]
use serdect::serde::{Deserialize, Serialize, de, ser};

/// Point on a Weierstrass curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint<C: PrimeCurveParams> {
    pub(crate) x: C::FieldElement,
    pub(crate) y: C::FieldElement,
    pub(crate) z: C::FieldElement,
}

impl<C> ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    /// Additive identity of the group a.k.a. the point at infinity.
    pub const IDENTITY: Self = Self {
        x: C::FieldElement::ZERO,
        y: C::FieldElement::ONE,
        z: C::FieldElement::ZERO,
    };

    /// Base point of the curve.
    pub const GENERATOR: Self = Self {
        x: C::GENERATOR.0,
        y: C::GENERATOR.1,
        z: C::FieldElement::ONE,
    };

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> AffinePoint<C> {
        <C::FieldElement as Field>::invert(&self.z)
            .map(|zinv| self.to_affine_internal(zinv))
            .unwrap_or(AffinePoint::IDENTITY)
    }

    pub(super) fn to_affine_internal(self, zinv: C::FieldElement) -> AffinePoint<C> {
        AffinePoint {
            x: self.x * &zinv,
            y: self.y * &zinv,
            infinity: 0,
        }
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
        C::PointArithmetic::add(self, other)
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint<C>) -> Self {
        C::PointArithmetic::add_mixed(self, other)
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
    pub fn mul(&self, k: &Scalar<C>) -> Self {
        let table = LookupTable::new(*self);
        let digits = Radix16Decomposition::new(k);
        lincomb::<C>(&[table], &[digits])
    }

    /// Returns `[k] self` computed in variable time.
    pub fn mul_vartime(&self, k: &Scalar<C>) -> Self {
        let table = LookupTable::new(*self);
        let digits = Radix16Decomposition::new(k);
        lincomb_vartime::<C>(&[table], &[digits])
    }
}

impl<C> ConditionallySelectable for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    #[inline(always)]
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
    C: PrimeCurveParams,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        let x_eq = (self.x * other.z).ct_eq(&(other.x * self.z));
        let y_eq = (self.y * other.z).ct_eq(&(other.y * self.z));

        x_eq & y_eq
    }
}

impl<C> ctutils::CtEq for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn ct_eq(&self, other: &Self) -> ctutils::Choice {
        ConstantTimeEq::ct_eq(self, other).into()
    }
}

impl<C> ctutils::CtSelect for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn ct_select(&self, other: &Self, choice: ctutils::Choice) -> Self {
        ConditionallySelectable::conditional_select(self, other, choice.into())
    }
}

impl<C> Default for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl<C> DefaultIsZeroes for ProjectivePoint<C> where C: PrimeCurveParams {}

impl<C: PrimeCurveParams> Double for ProjectivePoint<C> {
    fn double(&self) -> Self {
        C::PointArithmetic::double(self)
    }
}

impl<C> Eq for ProjectivePoint<C> where C: PrimeCurveParams {}

impl<C> From<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(p: AffinePoint<C>) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: C::FieldElement::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl<C> From<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(p: &AffinePoint<C>) -> Self {
        Self::from(*p)
    }
}

impl<C> From<NonIdentity<ProjectivePoint<C>>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(p: NonIdentity<ProjectivePoint<C>>) -> Self {
        p.to_point()
    }
}

impl<C> From<PublicKey<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(public_key: PublicKey<C>) -> ProjectivePoint<C> {
        AffinePoint::from(public_key).into()
    }
}

impl<C> From<&PublicKey<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from(public_key: &PublicKey<C>) -> ProjectivePoint<C> {
        AffinePoint::<C>::from(public_key).into()
    }
}

impl<C> FromSec1Point<C> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn from_sec1_point(p: &Sec1Point<C>) -> ctutils::CtOption<Self> {
        AffinePoint::<C>::from_sec1_point(p).map(Self::from)
    }
}

impl<C> Generate for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        AffinePoint::try_generate_from_rng(rng).map(Self::from)
    }
}

//
// `group` trait impls
//

/// Prime order elliptic curves have a cofactor of 1.
impl<C> CofactorGroup for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Subgroup = ProjectivePoint<C>;

    fn clear_cofactor(&self) -> Self::Subgroup {
        *self
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self, Choice::from(1))
    }

    fn is_torsion_free(&self) -> Choice {
        Choice::from(1)
    }
}

impl<C> CurveGroup for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Affine = AffinePoint<C>;

    fn to_affine(&self) -> AffinePoint<C> {
        ProjectivePoint::to_affine(self)
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn batch_normalize(projective: &[Self], affine: &mut [Self::Affine]) {
        assert_eq!(projective.len(), affine.len());
        let mut zs = vec![C::FieldElement::ZERO; projective.len()];
        let mut scratch = vec![C::FieldElement::ZERO; projective.len()];
        batch_normalize_generic(projective, &mut zs, &mut scratch, affine);
    }
}

impl<C> Group for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Scalar = Scalar<C>;

    fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> core::result::Result<Self, R::Error> {
        AffinePoint::try_random(rng).map(Self::from)
    }

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    #[inline]
    fn mul_by_generator(scalar: &Self::Scalar) -> Self {
        C::Backend::mul_by_generator(scalar)
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::IDENTITY)
    }

    fn double(&self) -> Self {
        Double::double(self)
    }
}

impl<C> GroupEncoding for ProjectivePoint<C>
where
    C: PrimeCurveParams,
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

impl<C> PrimeCurve for ProjectivePoint<C> where C: PrimeCurveParams {}
impl<C> PrimeGroup for ProjectivePoint<C> where C: PrimeCurveParams {}

//
// Batch trait impls
//

impl<const N: usize, C> BatchNormalize<[ProjectivePoint<C>; N]> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = [<Self as CurveGroup>::Affine; N];

    #[inline]
    fn batch_normalize(points: &[Self; N]) -> [<Self as CurveGroup>::Affine; N] {
        let mut zs = [C::FieldElement::ZERO; N];
        let mut scratch = [C::FieldElement::ZERO; N];
        let mut affine_points = [C::AffinePoint::IDENTITY; N];
        batch_normalize_generic(points, &mut zs, &mut scratch, &mut affine_points);
        affine_points
    }
}

#[cfg(feature = "alloc")]
impl<C> BatchNormalize<[ProjectivePoint<C>]> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = Vec<<Self as CurveGroup>::Affine>;

    #[inline]
    fn batch_normalize(points: &[Self]) -> Vec<<Self as CurveGroup>::Affine> {
        let mut zs = vec![C::FieldElement::ZERO; points.len()];
        let mut scratch = vec![C::FieldElement::ZERO; points.len()];
        let mut affine_points = vec![AffinePoint::IDENTITY; points.len()];
        batch_normalize_generic(points, &mut zs, &mut scratch, &mut affine_points);
        affine_points
    }
}

/// Generic implementation of batch normalization.
fn batch_normalize_generic<C>(
    points: &[ProjectivePoint<C>],
    zs: &mut [C::FieldElement],
    scratch: &mut [C::FieldElement],
    out: &mut [AffinePoint<C>],
) where
    C: PrimeCurveParams,
{
    debug_assert_eq!(points.len(), zs.len());
    debug_assert_eq!(points.len(), scratch.len());
    debug_assert_eq!(points.len(), out.len());

    for (z, point) in zs.iter_mut().zip(points) {
        *z = point.z;
    }

    // Zero `zs` (identity) are handled explicitly below, so the `Choice` here is informational only
    let _ = C::FieldElement::batch_invert_in_place(zs, scratch);

    for i in 0..out.len() {
        out[i] = C::AffinePoint::conditional_select(
            &points[i].to_affine_internal(zs[i]),
            &C::AffinePoint::IDENTITY,
            points[i].z.ct_eq(&C::FieldElement::ZERO),
        );
    }
}

impl<C> LinearCombination<[(Self, Scalar<C>)]> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    #[cfg(feature = "alloc")]
    fn lincomb(points_and_scalars: &[(Self, Scalar<C>)]) -> Self {
        let tables: Vec<_> = points_and_scalars
            .iter()
            .map(|(point, _)| LookupTable::new(*point))
            .collect();
        let digits: Vec<_> = points_and_scalars
            .iter()
            .map(|(_, scalar)| Radix16Decomposition::new(scalar))
            .collect();

        lincomb::<C>(&tables, &digits)
    }

    #[cfg(feature = "alloc")]
    fn lincomb_vartime(points_and_scalars: &[(Self, Scalar<C>)]) -> Self {
        let tables: Vec<_> = points_and_scalars
            .iter()
            .map(|(point, _)| LookupTable::new(*point))
            .collect();
        let digits: Vec<_> = points_and_scalars
            .iter()
            .map(|(_, scalar)| Radix16Decomposition::new(scalar))
            .collect();

        lincomb_vartime::<C>(&tables, &digits)
    }
}

impl<C, const N: usize> LinearCombination<[(Self, Scalar<C>); N]> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn lincomb(points_and_scalars: &[(Self, Scalar<C>); N]) -> Self {
        let tables: [_; N] = array::from_fn(|index| LookupTable::new(points_and_scalars[index].0));
        let digits: [_; N] =
            array::from_fn(|index| Radix16Decomposition::new(&points_and_scalars[index].1));

        lincomb::<C>(&tables, &digits)
    }

    fn lincomb_vartime(points_and_scalars: &[(Self, Scalar<C>); N]) -> Self {
        let tables: [_; N] = array::from_fn(|index| LookupTable::new(points_and_scalars[index].0));
        let digits: [_; N] =
            array::from_fn(|index| Radix16Decomposition::new(&points_and_scalars[index].1));

        lincomb_vartime::<C>(&tables, &digits)
    }
}

fn lincomb<C: PrimeCurveParams>(
    tables: &[LookupTable<ProjectivePoint<C>>],
    digits: &[Radix16Decomposition<Radix16Digits<C>>],
) -> ProjectivePoint<C> {
    debug_assert_eq!(tables.len(), digits.len());
    debug_assert!(!digits.is_empty());

    let d = Radix16Digits::<C>::USIZE;
    let mut q = ProjectivePoint::IDENTITY;

    for (table, digit) in zip(tables, digits) {
        q = q.add(&table.select(digit[d - 1]));
    }

    for i in (0..d - 1).rev() {
        for _ in 0..4 {
            q.double_in_place();
        }

        for (table, digit) in zip(tables, digits) {
            q = q.add(&table.select(digit[i]));
        }
    }

    q
}

fn lincomb_vartime<C: PrimeCurveParams>(
    tables: &[LookupTable<ProjectivePoint<C>>],
    digits: &[Radix16Decomposition<Radix16Digits<C>>],
) -> ProjectivePoint<C> {
    debug_assert_eq!(tables.len(), digits.len());
    debug_assert!(!digits.is_empty());

    let d = Radix16Digits::<C>::USIZE;
    let mut q = ProjectivePoint::IDENTITY;

    for (table, digit) in zip(tables, digits) {
        q = q.add(&table.select_vartime(digit[d - 1]));
    }

    for i in (0..d - 1).rev() {
        for _ in 0..4 {
            q.double_in_place();
        }

        for (table, digit) in zip(tables, digits) {
            q = q.add(&table.select_vartime(digit[i]));
        }
    }

    q
}

impl<C> PartialEq for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C> ToSec1Point<C> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn to_sec1_point(&self, compress: bool) -> Sec1Point<C> {
        self.to_affine().to_sec1_point(compress)
    }
}

/// The constant-time alternative is available at [`NonIdentity::new()`].
impl<C> TryFrom<ProjectivePoint<C>> for NonIdentity<ProjectivePoint<C>>
where
    C: PrimeCurveParams,
{
    type Error = Error;

    fn try_from(point: ProjectivePoint<C>) -> Result<Self> {
        NonIdentity::new(point).into_option().ok_or(Error)
    }
}

impl<C> TryFrom<ProjectivePoint<C>> for PublicKey<C>
where
    C: PrimeCurveParams,
{
    type Error = Error;

    fn try_from(point: ProjectivePoint<C>) -> Result<PublicKey<C>> {
        PublicKey::try_from(&point)
    }
}

impl<C> TryFrom<&ProjectivePoint<C>> for PublicKey<C>
where
    C: PrimeCurveParams,
{
    type Error = Error;

    fn try_from(point: &ProjectivePoint<C>) -> Result<PublicKey<C>> {
        AffinePoint::<C>::from(point).try_into()
    }
}

//
// `core::ops` trait impls
//

impl<C> Add<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(&self, &other)
    }
}

impl<C> Add<&ProjectivePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(self, other)
    }
}

impl<C> Add<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add(&self, other)
    }
}

impl<C> AddAssign<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: ProjectivePoint<C>) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl<C> AddAssign<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: &ProjectivePoint<C>) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl<C> Add<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(&self, &other)
    }
}

impl<C> Add<&AffinePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl<C> Add<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn add(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl<C> AddAssign<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl<C> AddAssign<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn add_assign(&mut self, rhs: &AffinePoint<C>) {
        *self = ProjectivePoint::add_mixed(self, rhs);
    }
}

impl<C> Sum for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}

impl<'a, C> Sum<&'a ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sum<I: Iterator<Item = &'a ProjectivePoint<C>>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<C> Sub<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(&self, &other)
    }
}

impl<C> Sub<&ProjectivePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(self, other)
    }
}

impl<C> Sub<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub(&self, other)
    }
}

impl<C> SubAssign<ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: ProjectivePoint<C>) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl<C> SubAssign<&ProjectivePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: &ProjectivePoint<C>) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl<C> Sub<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(&self, &other)
    }
}

impl<C> Sub<&AffinePoint<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl<C> Sub<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn sub(self, other: &AffinePoint<C>) -> ProjectivePoint<C> {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl<C> SubAssign<AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl<C> SubAssign<&AffinePoint<C>> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn sub_assign(&mut self, rhs: &AffinePoint<C>) {
        *self = ProjectivePoint::sub_mixed(self, rhs);
    }
}

impl<C, S> Mul<S> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    type Output = Self;

    fn mul(self, scalar: S) -> Self {
        ProjectivePoint::mul(&self, scalar.borrow())
    }
}

impl<C, S> Mul<S> for &ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    type Output = ProjectivePoint<C>;

    fn mul(self, scalar: S) -> ProjectivePoint<C> {
        ProjectivePoint::mul(self, scalar.borrow())
    }
}

impl<C> Mul<&Scalar<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
    ProjectivePoint<C>: Double,
{
    type Output = ProjectivePoint<C>;

    fn mul(self, scalar: &Scalar<C>) -> ProjectivePoint<C> {
        ProjectivePoint::mul(self, scalar)
    }
}

impl<C, S> MulVartime<S> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    fn mul_vartime(self, scalar: S) -> Self {
        ProjectivePoint::mul_vartime(&self, scalar.borrow())
    }
}

impl<C, S> MulVartime<S> for &ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    fn mul_vartime(self, scalar: S) -> ProjectivePoint<C> {
        ProjectivePoint::mul_vartime(self, scalar.borrow())
    }
}

impl<C> MulVartime<&Scalar<C>> for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
    ProjectivePoint<C>: Double,
{
    fn mul_vartime(self, scalar: &Scalar<C>) -> ProjectivePoint<C> {
        ProjectivePoint::mul_vartime(self, scalar)
    }
}

impl<C> MulByGeneratorVartime for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    #[inline]
    fn mul_by_generator_vartime(scalar: &Scalar<C>) -> Self {
        C::Backend::mul_by_generator_vartime(scalar)
    }

    #[inline]
    fn mul_by_generator_and_mul_add_vartime(
        a: &Self::Scalar,
        b_scalar: &Self::Scalar,
        b_point: &Self,
    ) -> Self {
        C::Backend::mul_by_generator_and_mul_add_vartime(a, b_scalar, b_point)
    }
}

impl<C, S> MulAssign<S> for ProjectivePoint<C>
where
    Self: Double,
    C: PrimeCurveParams,
    S: Borrow<Scalar<C>>,
{
    fn mul_assign(&mut self, scalar: S) {
        *self = ProjectivePoint::mul(self, scalar.borrow());
    }
}

impl<C> Neg for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn neg(self) -> ProjectivePoint<C> {
        ProjectivePoint::neg(&self)
    }
}

impl<C> Neg for &ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    type Output = ProjectivePoint<C>;

    fn neg(self) -> ProjectivePoint<C> {
        ProjectivePoint::neg(self)
    }
}

//
// serde support
//

#[cfg(feature = "serde")]
impl<C> Serialize for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.to_affine().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, C> Deserialize<'de> for ProjectivePoint<C>
where
    C: PrimeCurveParams,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        AffinePoint::<C>::deserialize(deserializer).map(Self::from)
    }
}
