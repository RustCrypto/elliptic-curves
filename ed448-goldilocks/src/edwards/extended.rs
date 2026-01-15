use core::borrow::Borrow;
use core::fmt::{Display, Formatter, LowerHex, Result as FmtResult, UpperHex};
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::{
    GOLDILOCKS_BASE_POINT, MontgomeryPoint, U57, U448,
    curve::{
        scalar_mul::variable_base,
        twedwards::{
            IsogenyMap, IsogenyMapResult, extensible::ExtensiblePoint as TwistedExtensiblePoint,
        },
    },
    edwards::{
        CompressedEdwardsY,
        affine::{AffinePoint, PointBytes},
        scalar::EdwardsScalar,
    },
    field::{ConstMontyType, FieldElement},
};
use elliptic_curve::{
    BatchNormalize, CurveGroup, Error, Generate,
    array::Array,
    ctutils,
    group::{Group, GroupEncoding, cofactor::CofactorGroup, prime::PrimeGroup},
    ops::{BatchInvert, LinearCombination},
    point::NonIdentity,
};
use rand_core::{TryCryptoRng, TryRngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

/// Represent points on the (untwisted) edwards curve using Extended Homogenous Projective Co-ordinates
/// (x, y) -> (X/Z, Y/Z, Z, T)
/// a = 1, d = -39081
/// XXX: Make this more descriptive
/// Should this be renamed to EdwardsPoint so that we are consistent with Dalek crypto? Necessary as ExtendedPoint is not regular lingo?
#[derive(Copy, Clone, Debug)]
pub struct EdwardsPoint {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T: FieldElement,
}

impl Default for EdwardsPoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Display for EdwardsPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ X: {}, Y: {}, Z: {}, T: {} }}",
            self.X, self.Y, self.Z, self.T
        )
    }
}

impl LowerHex for EdwardsPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ X: {:x}, Y: {:x}, Z: {:x}, T: {:x} }}",
            self.X, self.Y, self.Z, self.T
        )
    }
}

impl UpperHex for EdwardsPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ X: {:X}, Y: {:X}, Z: {:X}, T: {:X} }}",
            self.X, self.Y, self.Z, self.T
        )
    }
}

impl ConditionallySelectable for EdwardsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        EdwardsPoint {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T: FieldElement::conditional_select(&a.T, &b.T, choice),
        }
    }
}

impl ConstantTimeEq for EdwardsPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let XZ = self.X * other.Z;
        let ZX = self.Z * other.X;

        let YZ = self.Y * other.Z;
        let ZY = self.Z * other.Y;

        (XZ.ct_eq(&ZX)) & (YZ.ct_eq(&ZY))
    }
}

impl ctutils::CtEq for EdwardsPoint {
    fn ct_eq(&self, other: &Self) -> ctutils::Choice {
        ConstantTimeEq::ct_eq(self, other).into()
    }
}

impl ctutils::CtSelect for EdwardsPoint {
    fn ct_select(&self, other: &Self, choice: ctutils::Choice) -> Self {
        ConditionallySelectable::conditional_select(self, other, choice.into())
    }
}

impl Eq for EdwardsPoint {}
impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &EdwardsPoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Generate for EdwardsPoint {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Self::try_from_rng(rng)
    }
}

impl Group for EdwardsPoint {
    type Scalar = EdwardsScalar;

    fn try_from_rng<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryRngCore + ?Sized,
    {
        loop {
            let point = AffinePoint::try_from_rng(rng)?;
            if point != AffinePoint::IDENTITY {
                break Ok(point.into());
            }
        }
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

    fn double(&self) -> Self {
        Self::double(self)
    }
}

impl GroupEncoding for EdwardsPoint {
    type Repr = Array<u8, U57>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let mut value = [0u8; 57];
        value.copy_from_slice(bytes);
        CompressedEdwardsY(value)
            .decompress()
            .map(|point| point.to_edwards())
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let mut value = [0u8; 57];
        value.copy_from_slice(bytes);
        CompressedEdwardsY(value)
            .decompress()
            .map(|point| point.to_edwards())
    }

    fn to_bytes(&self) -> Self::Repr {
        Self::Repr::from(self.to_affine().compress().0)
    }
}

impl CofactorGroup for EdwardsPoint {
    type Subgroup = EdwardsPoint;

    fn clear_cofactor(&self) -> Self::Subgroup {
        self.double().double()
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self.clear_cofactor(), self.is_torsion_free())
    }

    fn is_torsion_free(&self) -> Choice {
        Self::is_torsion_free(self)
    }
}

impl PrimeGroup for EdwardsPoint {}

#[cfg(feature = "alloc")]
impl From<EdwardsPoint> for Vec<u8> {
    fn from(value: EdwardsPoint) -> Self {
        Self::from(&value)
    }
}

#[cfg(feature = "alloc")]
impl From<&EdwardsPoint> for Vec<u8> {
    fn from(value: &EdwardsPoint) -> Self {
        value.to_affine().compress().0.to_vec()
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Vec<u8>> for EdwardsPoint {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<&Vec<u8>> for EdwardsPoint {
    type Error = &'static str;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for EdwardsPoint {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes =
            <PointBytes>::try_from(value).map_err(|_| "Invalid length, expected 57 bytes")?;
        Self::try_from(bytes)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Box<[u8]>> for EdwardsPoint {
    type Error = &'static str;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl TryFrom<PointBytes> for EdwardsPoint {
    type Error = &'static str;

    fn try_from(value: PointBytes) -> Result<Self, Self::Error> {
        CompressedEdwardsY(value)
            .decompress()
            .into_option()
            .map(|point| point.to_edwards())
            .ok_or("Invalid point")
    }
}

impl TryFrom<&PointBytes> for EdwardsPoint {
    type Error = &'static str;

    fn try_from(value: &PointBytes) -> Result<Self, Self::Error> {
        Self::try_from(*value)
    }
}

impl From<EdwardsPoint> for PointBytes {
    fn from(value: EdwardsPoint) -> Self {
        value.to_affine().compress().into()
    }
}

impl From<&EdwardsPoint> for PointBytes {
    fn from(value: &EdwardsPoint) -> Self {
        Self::from(*value)
    }
}

impl From<EdwardsPoint> for AffinePoint {
    fn from(value: EdwardsPoint) -> Self {
        value.to_affine()
    }
}

impl From<&AffinePoint> for EdwardsPoint {
    fn from(value: &AffinePoint) -> Self {
        value.to_edwards()
    }
}

impl From<AffinePoint> for EdwardsPoint {
    fn from(value: AffinePoint) -> Self {
        value.to_edwards()
    }
}

impl From<&EdwardsPoint> for AffinePoint {
    fn from(value: &EdwardsPoint) -> Self {
        value.to_affine()
    }
}

impl<const N: usize> LinearCombination<[(EdwardsPoint, EdwardsScalar); N]> for EdwardsPoint {}

impl LinearCombination<[(EdwardsPoint, EdwardsScalar)]> for EdwardsPoint {}

impl CurveGroup for EdwardsPoint {
    type AffineRepr = AffinePoint;

    fn to_affine(&self) -> AffinePoint {
        Self::to_affine(self)
    }

    #[cfg(feature = "alloc")]
    #[inline]
    fn batch_normalize(projective: &[Self], affine: &mut [Self::AffineRepr]) {
        assert_eq!(projective.len(), affine.len());
        let mut zs = alloc::vec![FieldElement::ONE; projective.len()];
        batch_normalize_generic(projective, zs.as_mut_slice(), affine);
    }
}

impl EdwardsPoint {
    /// Generator for the prime subgroup
    pub const GENERATOR: Self = GOLDILOCKS_BASE_POINT;
    /// Identity point
    pub const IDENTITY: Self = Self {
        X: FieldElement::ZERO,
        Y: FieldElement::ONE,
        Z: FieldElement::ONE,
        T: FieldElement::ZERO,
    };

    /// Convert this point to [`MontgomeryPoint`]
    pub fn to_montgomery(&self) -> MontgomeryPoint {
        // u = y^2 * [(1-dy^2)/(1-y^2)]

        let affine = self.to_affine();

        let yy = affine.y.square();
        let dyy = FieldElement::EDWARDS_D * yy;

        let u = yy * (FieldElement::ONE - dyy) * (FieldElement::ONE - yy).invert();

        MontgomeryPoint(u.to_bytes())
    }

    /// Generic scalar multiplication to compute s*P
    pub fn scalar_mul(&self, scalar: &EdwardsScalar) -> Self {
        // Compute floor(s/4)
        let scalar_div_four = scalar.div_by_2().div_by_2();

        // Use isogeny and dual isogeny to compute phi^-1((s/4) * phi(P))
        variable_base(&self.to_twisted().to_extended(), &scalar_div_four)
            .to_extended()
            .to_untwisted()
    }

    /// Add two points
    //https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf (3.1)
    // These formulas are unified, so for now we can use it for doubling. Will refactor later for speed
    pub fn add(&self, other: &EdwardsPoint) -> Self {
        let aXX = self.X * other.X; // aX1X2
        let dTT = FieldElement::EDWARDS_D * self.T * other.T; // dT1T2
        let ZZ = self.Z * other.Z; // Z1Z2
        let YY = self.Y * other.Y;

        let X = {
            let x_1 = (self.X * other.Y) + (self.Y * other.X);
            let x_2 = ZZ - dTT;
            x_1 * x_2
        };
        let Y = {
            let y_1 = YY - aXX;
            let y_2 = ZZ + dTT;
            y_1 * y_2
        };

        let T = {
            let t_1 = YY - aXX;
            let t_2 = (self.X * other.Y) + (self.Y * other.X);
            t_1 * t_2
        };

        let Z = { (ZZ - dTT) * (ZZ + dTT) };

        EdwardsPoint { X, Y, Z, T }
    }

    /// Double this point
    // XXX: See comment on addition, the formula is unified, so this will do for now
    //https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf (3.1)
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Check if this point is on the curve
    pub fn is_on_curve(&self) -> Choice {
        let XY = self.X * self.Y;
        let ZT = self.Z * self.T;

        // Y^2 + X^2 == Z^2 - T^2 * D

        let YY = self.Y.square();
        let XX = self.X.square();
        let ZZ = self.Z.square();
        let TT = self.T.square();
        let lhs = YY + XX;
        let rhs = ZZ + TT * FieldElement::EDWARDS_D;

        XY.ct_eq(&ZT) & lhs.ct_eq(&rhs)
    }

    /// Convert this point to an [`AffinePoint`].
    pub fn to_affine(&self) -> AffinePoint {
        let INV_Z = self.Z.invert();

        let x = self.X * INV_Z;
        let y = self.Y * INV_Z;

        AffinePoint { x, y }
    }

    pub(crate) fn to_twisted(self) -> TwistedExtensiblePoint {
        let IsogenyMapResult { X, Y, Z, T1, T2 } = IsogenyMap {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T: self.T,
        }
        .map(|f| f);

        TwistedExtensiblePoint { X, Y, Z, T1, T2 }
    }

    /// Compute the negation of this point's `x`-coordinate.
    pub fn negate(&self) -> Self {
        EdwardsPoint {
            X: -self.X,
            Y: self.Y,
            Z: self.Z,
            T: -self.T,
        }
    }

    /// Compute the negation of this point's `y`-coordinate.
    pub fn torque(&self) -> Self {
        EdwardsPoint {
            X: -self.X,
            Y: -self.Y,
            Z: self.Z,
            T: self.T,
        }
    }

    /// Determine if this point is “torsion-free”, i.e., is contained in
    /// the prime-order subgroup.
    ///
    /// # Return
    ///
    /// * `true` if `self` has zero torsion component and is in the
    ///   prime-order subgroup;
    /// * `false` if `self` has a nonzero torsion component and is not
    ///   in the prime-order subgroup.
    // See https://eprint.iacr.org/2022/1164.
    pub fn is_torsion_free(&self) -> Choice {
        const A: FieldElement = FieldElement(ConstMontyType::new(&U448::from_be_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffeceaf",
        )));
        const A1: FieldElement = FieldElement(ConstMontyType::new(&U448::from_u64(156320)));
        const MINUS_SQRT_B1: FieldElement = FieldElement(ConstMontyType::new(&U448::from_be_hex(
            "749a7410536c225f1025ca374176557d7839611d691caad26d74a1fca5cfad15f196642c0a4484b67f321025577cc6b5a6f443c2eaa36327",
        )));

        let mut e = self.X * (self.Z - self.Y);
        let ee = e.square();
        let mut u = FieldElement::A_PLUS_TWO_OVER_FOUR * (self.Z + self.Y) * e * self.X;
        let w = self.Z.double() * (self.Z - self.Y);

        let u2 = u.double().double();
        let w2 = w.double();

        let mut w1 = u2.unchecked_sqrt();
        let mut ok = w1.square().ct_eq(&u2);
        let u1 = (u2 - A1 * ee - w1 * w2).div_by_2();

        // If `u1` happens not to be a square, then `sqrt(u1)` returns `sqrt(-u1)`
        // in that case (since we are in a finite field GF(q) with q = 3 mod 4,
        // if `u1` is not a square then `-u1` must be a square). In such a case, we
        // should replace `(u1,w1)` with `((B1*e^4)/u1, -w1)`. To avoid the division,
        // we instead switch to an isomorphic curve; namely:
        //   u2 = B1*(e^4)*u1
        //   w2 = -w1*u1
        //   e2 = e*u1
        // Then:
        //   w = sqrt(u2) = sqrt(-B1)*(e^2)*sqrt(-u1)
        //   u = (w^2 - A*e^2 - w*w1)/2
        let mut w = u1.unchecked_sqrt();
        let u1_is_square = w.square().ct_eq(&u1);
        w1.conditional_assign(&-(w1 * u1), !u1_is_square);
        e.conditional_assign(&(e * u1), !u1_is_square);
        w.conditional_assign(&(MINUS_SQRT_B1 * ee * w), !u1_is_square);
        u = (w.square() - A * e.square() - w * w1).div_by_2();

        ok &= u.is_square();

        // If the source point was a low-order point, then the computations
        // above are incorrect. We handle this case here; among the
        // low-order points, only the neutral point is in the prime-order
        // subgroup.
        let is_low_order = self.X.is_zero() | self.Y.is_zero();
        let is_neutral = self.Y.ct_eq(&self.Z);
        ok ^= is_low_order & (ok ^ is_neutral);

        ok
    }
}

impl From<NonIdentity<EdwardsPoint>> for EdwardsPoint {
    fn from(p: NonIdentity<EdwardsPoint>) -> Self {
        p.to_point()
    }
}

/// The constant-time alternative is available at [`NonIdentity::new()`].
impl TryFrom<EdwardsPoint> for NonIdentity<EdwardsPoint> {
    type Error = Error;

    fn try_from(point: EdwardsPoint) -> Result<Self, Error> {
        NonIdentity::new(point).into_option().ok_or(Error)
    }
}

// ------------------------------------------------------------------------
// Addition and Subtraction
// ------------------------------------------------------------------------

impl Add<&EdwardsPoint> for &EdwardsPoint {
    type Output = EdwardsPoint;

    fn add(self, other: &EdwardsPoint) -> EdwardsPoint {
        self.add(other)
    }
}

define_add_variants!(
    LHS = EdwardsPoint,
    RHS = EdwardsPoint,
    Output = EdwardsPoint
);

define_add_variants!(LHS = EdwardsPoint, RHS = AffinePoint, Output = EdwardsPoint);

define_add_variants!(LHS = AffinePoint, RHS = EdwardsPoint, Output = EdwardsPoint);

impl Add<&AffinePoint> for &EdwardsPoint {
    type Output = EdwardsPoint;

    fn add(self, other: &AffinePoint) -> EdwardsPoint {
        *self + *other
    }
}

impl Add<&EdwardsPoint> for &AffinePoint {
    type Output = EdwardsPoint;

    fn add(self, other: &EdwardsPoint) -> EdwardsPoint {
        *other + *self
    }
}

impl<'b> AddAssign<&'b EdwardsPoint> for EdwardsPoint {
    fn add_assign(&mut self, _rhs: &'b EdwardsPoint) {
        *self = *self + _rhs;
    }
}

define_add_assign_variants!(LHS = EdwardsPoint, RHS = EdwardsPoint);

impl AddAssign<&AffinePoint> for EdwardsPoint {
    fn add_assign(&mut self, rhs: &AffinePoint) {
        *self += rhs.to_edwards();
    }
}

define_add_assign_variants!(LHS = EdwardsPoint, RHS = AffinePoint);

impl AddAssign<&EdwardsPoint> for AffinePoint {
    fn add_assign(&mut self, rhs: &EdwardsPoint) {
        *self = (self.to_edwards() + rhs).to_affine();
    }
}

define_add_assign_variants!(LHS = AffinePoint, RHS = EdwardsPoint);

impl Sub<&EdwardsPoint> for &EdwardsPoint {
    type Output = EdwardsPoint;

    fn sub(self, other: &EdwardsPoint) -> EdwardsPoint {
        self.add(&other.negate())
    }
}

define_sub_variants!(
    LHS = EdwardsPoint,
    RHS = EdwardsPoint,
    Output = EdwardsPoint
);

impl Sub<&AffinePoint> for &EdwardsPoint {
    type Output = EdwardsPoint;

    fn sub(self, other: &AffinePoint) -> EdwardsPoint {
        *self - other.to_edwards()
    }
}

define_sub_variants!(LHS = EdwardsPoint, RHS = AffinePoint, Output = EdwardsPoint);

impl Sub<&EdwardsPoint> for &AffinePoint {
    type Output = EdwardsPoint;

    fn sub(self, other: &EdwardsPoint) -> EdwardsPoint {
        *self - other
    }
}

define_sub_variants!(LHS = AffinePoint, RHS = EdwardsPoint, Output = EdwardsPoint);

impl<'b> SubAssign<&'b EdwardsPoint> for EdwardsPoint {
    fn sub_assign(&mut self, _rhs: &'b EdwardsPoint) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(LHS = EdwardsPoint, RHS = EdwardsPoint);

impl SubAssign<&AffinePoint> for EdwardsPoint {
    fn sub_assign(&mut self, rhs: &AffinePoint) {
        *self -= rhs.to_edwards();
    }
}

define_sub_assign_variants!(LHS = EdwardsPoint, RHS = AffinePoint);

impl SubAssign<&EdwardsPoint> for AffinePoint {
    fn sub_assign(&mut self, rhs: &EdwardsPoint) {
        *self = (self.to_edwards() - rhs).to_affine();
    }
}

define_sub_assign_variants!(LHS = AffinePoint, RHS = EdwardsPoint);

impl<T> Sum<T> for EdwardsPoint
where
    T: Borrow<EdwardsPoint>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::IDENTITY, |acc, item| acc + item.borrow())
    }
}

// ------------------------------------------------------------------------
// Negation
// ------------------------------------------------------------------------

impl Neg for &EdwardsPoint {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        self.negate()
    }
}

impl Neg for EdwardsPoint {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        -&self
    }
}

// ------------------------------------------------------------------------
// Scalar multiplication
// ------------------------------------------------------------------------

impl<'b> MulAssign<&'b EdwardsScalar> for EdwardsPoint {
    fn mul_assign(&mut self, scalar: &'b EdwardsScalar) {
        let result = *self * scalar;
        *self = result;
    }
}

define_mul_assign_variants!(LHS = EdwardsPoint, RHS = EdwardsScalar);

define_mul_variants!(
    LHS = EdwardsPoint,
    RHS = EdwardsScalar,
    Output = EdwardsPoint
);

impl Mul<&EdwardsScalar> for &EdwardsPoint {
    type Output = EdwardsPoint;

    /// Scalar multiplication: compute `scalar * self`.
    fn mul(self, scalar: &EdwardsScalar) -> EdwardsPoint {
        self.scalar_mul(scalar)
    }
}

#[cfg(feature = "serde")]
impl serdect::serde::Serialize for EdwardsPoint {
    fn serialize<S: serdect::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_affine().compress().serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serdect::serde::Deserialize<'de> for EdwardsPoint {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let compressed = CompressedEdwardsY::deserialize(d)?;
        compressed
            .decompress()
            .into_option()
            .map(|point| point.to_edwards())
            .ok_or_else(|| serdect::serde::de::Error::custom("invalid point"))
    }
}

impl elliptic_curve::zeroize::DefaultIsZeroes for EdwardsPoint {}

impl<const N: usize> BatchNormalize<[EdwardsPoint; N]> for EdwardsPoint {
    type Output = [<Self as CurveGroup>::AffineRepr; N];

    #[inline]
    fn batch_normalize(points: &[Self; N]) -> [<Self as CurveGroup>::AffineRepr; N] {
        let zs = [FieldElement::ONE; N];
        let mut affine_points = [AffinePoint::IDENTITY; N];
        batch_normalize_generic(points, zs, &mut affine_points);
        affine_points
    }
}

#[cfg(feature = "alloc")]
impl BatchNormalize<[EdwardsPoint]> for EdwardsPoint {
    type Output = Vec<<Self as CurveGroup>::AffineRepr>;

    #[inline]
    fn batch_normalize(points: &[Self]) -> Vec<<Self as CurveGroup>::AffineRepr> {
        use alloc::vec;

        let mut zs = vec![FieldElement::ONE; points.len()];
        let mut affine_points = vec![AffinePoint::IDENTITY; points.len()];
        batch_normalize_generic(points, zs.as_mut_slice(), &mut affine_points);
        affine_points
    }
}

/// Generic implementation of batch normalization.
fn batch_normalize_generic<P, Z, I, O>(points: &P, mut zs: Z, out: &mut O)
where
    FieldElement: BatchInvert<Z, Output = CtOption<I>>,
    P: AsRef<[EdwardsPoint]> + ?Sized,
    Z: AsMut<[FieldElement]>,
    I: AsRef<[FieldElement]>,
    O: AsMut<[AffinePoint]> + ?Sized,
{
    let points = points.as_ref();
    let out = out.as_mut();

    for (i, point) in points.iter().enumerate() {
        // Even a single zero value will fail inversion for the entire batch.
        // Put a dummy value (above `FieldElement::ONE`) so inversion succeeds
        // and treat that case specially later-on.
        zs.as_mut()[i].conditional_assign(&point.Z, !point.Z.ct_eq(&FieldElement::ZERO));
    }

    // This is safe to unwrap since we assured that all elements are non-zero
    let zs_inverses = <FieldElement as BatchInvert<Z>>::batch_invert(zs)
        .expect("all elements should be non-zero");

    for i in 0..out.len() {
        // If the `z` coordinate is non-zero, we can use it to invert;
        // otherwise it defaults to the `IDENTITY` value.
        out[i] = AffinePoint::conditional_select(
            &AffinePoint {
                x: points[i].X * zs_inverses.as_ref()[i],
                y: points[i].Y * zs_inverses.as_ref()[i],
            },
            &AffinePoint::IDENTITY,
            points[i].Z.ct_eq(&FieldElement::ZERO),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ed448;
    use elliptic_curve::Field;
    use getrandom::{SysRng, rand_core::TryRngCore};
    use hash2curve::{ExpandMsgXof, GroupDigest};
    use hex_literal::hex;
    use proptest::{prop_assert_eq, property_test};

    fn hex_to_field(hex: &'static str) -> FieldElement {
        assert_eq!(hex.len(), 56 * 2);
        let mut bytes =
            hex_literal::decode(&[hex.as_bytes()]).expect("Output array length should be correct");
        bytes.reverse();
        FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn test_isogeny() {
        let x = hex_to_field(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555",
        );
        let y = hex_to_field(
            "ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed",
        );
        let a = AffinePoint { x, y }.to_edwards();
        let twist_a = a.to_twisted().to_extended().to_untwisted();
        assert!(twist_a == a.double().double())
    }

    // XXX: Move this to constants folder to test all global constants
    #[test]
    fn derive_base_points() {
        use crate::{GOLDILOCKS_BASE_POINT, TWISTED_EDWARDS_BASE_POINT};

        // This was the original basepoint which had order 2q;
        let old_x = hex_to_field(
            "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E",
        );
        let old_y = hex_to_field(
            "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14",
        );
        let old_bp = AffinePoint { x: old_x, y: old_y }.to_edwards();

        // This is the new basepoint, that is in the ed448 paper
        let new_x = hex_to_field(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555",
        );
        let new_y = hex_to_field(
            "ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed",
        );
        let new_bp = AffinePoint { x: new_x, y: new_y }.to_edwards();

        // Doubling the old basepoint, should give us the new basepoint
        assert_eq!(old_bp.double(), new_bp);

        // XXX: Unfortunately, the test vectors in libdecaf currently use the old basepoint.
        // We need to update this. But for now, I use the old basepoint so that I can check against libdecaf

        assert_eq!(GOLDILOCKS_BASE_POINT, old_bp);

        // The Twisted basepoint can be derived by using the isogeny
        assert_eq!(old_bp.to_twisted(), TWISTED_EDWARDS_BASE_POINT)
    }

    #[test]
    fn test_is_on_curve() {
        let x = hex_to_field(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555",
        );
        let y = hex_to_field(
            "ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed",
        );
        let generated = AffinePoint { x, y }.to_edwards();
        assert_eq!(generated.is_on_curve().unwrap_u8(), 1u8);
    }
    #[test]
    fn test_compress_decompress() {
        let x = hex_to_field(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555",
        );
        let y = hex_to_field(
            "ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed",
        );
        let generated = AffinePoint { x, y };

        let decompressed_point = generated.compress().decompress();
        assert!(<Choice as Into<bool>>::into(decompressed_point.is_some()));

        assert!(generated == decompressed_point.unwrap());
    }
    #[test]
    fn test_decompress_compress() {
        let bytes = hex!(
            "649c6a53b109897d962d033f23d01fd4e1053dddf3746d2ddce9bd66aea38ccfc3df061df03ca399eb806312ab3037c0c31523142956ada780"
        );
        let compressed = CompressedEdwardsY(bytes);
        let decompressed = compressed.decompress().unwrap();

        let recompressed = decompressed.compress();

        assert_eq!(bytes, recompressed.0);
    }
    #[test]
    fn test_just_decompress() {
        let bytes = hex!(
            "649c6a53b109897d962d033f23d01fd4e1053dddf3746d2ddce9bd66aea38ccfc3df061df03ca399eb806312ab3037c0c31523142956ada780"
        );
        let compressed = CompressedEdwardsY(bytes);
        let decompressed = compressed.decompress().unwrap();

        assert_eq!(
            decompressed.x,
            hex_to_field(
                "39c41cea305d737df00de8223a0d5f4d48c8e098e16e9b4b2f38ac353262e119cb5ff2afd6d02464702d9d01c9921243fc572f9c718e2527"
            )
        );
        assert_eq!(
            decompressed.y,
            hex_to_field(
                "a7ad5629142315c3c03730ab126380eb99a33cf01d06dfc3cf8ca3ae66bde9dc2d6d74f3dd3d05e1d41fd0233f032d967d8909b1536a9c64"
            )
        );

        let bytes = hex!(
            "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        let compressed = CompressedEdwardsY(bytes);
        let decompressed = compressed.decompress().unwrap();

        assert_eq!(
            decompressed.x,
            hex_to_field(
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decompressed.y,
            hex_to_field(
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
            )
        );
    }
    #[test]
    fn test_is_torsion_free() {
        assert_eq!(EdwardsPoint::GENERATOR.is_torsion_free().unwrap_u8(), 1u8);
        assert_eq!(EdwardsPoint::IDENTITY.is_torsion_free().unwrap_u8(), 1u8);

        let bytes = hex!(
            "13b6714c7a5f53101bbec88f2f17cd30f42e37fae363a5474efb4197ed6005df5861ae178a0c2c16ad378b7befed0d0904b7ced35e9f674180"
        );
        let compressed = CompressedEdwardsY(bytes);
        let decompressed = compressed.decompress();
        assert_eq!(decompressed.is_none().unwrap_u8(), 1u8);
    }

    #[test]
    fn hash_with_test_vectors() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_";
        const MSGS: &[(&[u8], [u8; 56], [u8; 56])] = &[
            (b"", hex!("73036d4a88949c032f01507005c133884e2f0d81f9a950826245dda9e844fc78186c39daaa7147ead3e462cff60e9c6340b58134480b4d17"), hex!("94c1d61b43728e5d784ef4fcb1f38e1075f3aef5e99866911de5a234f1aafdc26b554344742e6ba0420b71b298671bbeb2b7736618634610")),
            (b"abc", hex!("4e0158acacffa545adb818a6ed8e0b870e6abc24dfc1dc45cf9a052e98469275d9ff0c168d6a5ac7ec05b742412ee090581f12aa398f9f8c"), hex!("894d3fa437b2d2e28cdc3bfaade035430f350ec5239b6b406b5501da6f6d6210ff26719cad83b63e97ab26a12df6dec851d6bf38e294af9a")),
            (b"abcdef0123456789", hex!("2c25b4503fadc94b27391933b557abdecc601c13ed51c5de68389484f93dbd6c22e5f962d9babf7a39f39f994312f8ca23344847e1fbf176"), hex!("d5e6f5350f430e53a110f5ac7fcc82a96cb865aeca982029522d32601e41c042a9dfbdfbefa2b0bdcdc3bc58cca8a7cd546803083d3a8548")),
            (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hex!("a1861a9464ae31249a0e60bf38791f3663049a3f5378998499a83292e159a2fecff838eb9bc6939e5c6ae76eb074ad4aae39b55b72ca0b9a"), hex!("580a2798c5b904f8adfec5bd29fb49b4633cd9f8c2935eb4a0f12e5dfa0285680880296bb729c6405337525fb5ed3dff930c137314f60401")),
            (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex!("987c5ac19dd4b47835466a50b2d9feba7c8491b8885a04edf577e15a9f2c98b203ec2cd3e5390b3d20bba0fa6fc3eecefb5029a317234401"), hex!("5e273fcfff6b007bb6771e90509275a71ff1480c459ded26fc7b10664db0a68aaa98bc7ecb07e49cf05b80ae5ac653fbdd14276bbd35ccbc")),
        ];

        for (msg, x, y) in MSGS {
            let p =
                hash2curve::hash_from_bytes::<Ed448, ExpandMsgXof<sha3::Shake256>>(&[msg], &[DST])
                    .unwrap();
            assert_eq!(p.is_on_curve().unwrap_u8(), 1u8);
            let p = p.to_affine();
            let mut xx = [0u8; 56];
            xx.copy_from_slice(&x[..]);
            xx.reverse();
            let mut yy = [0u8; 56];
            yy.copy_from_slice(&y[..]);
            yy.reverse();
            assert_eq!(p.x.to_bytes(), xx);
            assert_eq!(p.y.to_bytes(), yy);
        }
    }

    #[test]
    fn hash_fuzzing() {
        for _ in 0..25 {
            let mut msg = [0u8; 64];
            SysRng.try_fill_bytes(&mut msg).unwrap();
            let p = Ed448::hash_from_bytes(&msg, b"test DST").unwrap();
            assert_eq!(p.is_on_curve().unwrap_u8(), 1u8);
            assert_eq!(p.is_torsion_free().unwrap_u8(), 1u8);
        }
    }

    #[test]
    fn encode() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_NU_";
        const MSGS: &[(&[u8], [u8; 56], [u8; 56])] = &[
            (b"", hex!("eb5a1fc376fd73230af2de0f3374087cc7f279f0460114cf0a6c12d6d044c16de34ec2350c34b26bf110377655ab77936869d085406af71e"), hex!("df5dcea6d42e8f494b279a500d09e895d26ac703d75ca6d118e8ca58bf6f608a2a383f292fce1563ff995dce75aede1fdc8e7c0c737ae9ad")),
            (b"abc", hex!("4623a64bceaba3202df76cd8b6e3daf70164f3fcbda6d6e340f7fab5cdf89140d955f722524f5fe4d968fef6ba2853ff4ea086c2f67d8110"), hex!("abaac321a169761a8802ab5b5d10061fec1a83c670ac6bc95954700317ee5f82870120e0e2c5a21b12a0c7ad17ebd343363604c4bcecafd1")),
            (b"abcdef0123456789", hex!("e9eb562e76db093baa43a31b7edd04ec4aadcef3389a7b9c58a19cf87f8ae3d154e134b6b3ed45847a741e33df51903da681629a4b8bcc2e"), hex!("0cf6606927ad7eb15dbc193993bc7e4dda744b311a8ec4274c8f738f74f605934582474c79260f60280fe35bd37d4347e59184cbfa12cbc4")),
            (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hex!("122a3234d34b26c69749f23356452bf9501efa2d94859d5ef741fef024156d9d191a03a2ad24c38186f93e02d05572575968b083d8a39738"), hex!("ddf55e74eb4414c2c1fa4aa6bc37c4ab470a3fed6bb5af1e43570309b162fb61879bb15f9ea49c712efd42d0a71666430f9f0d4a20505050")),
            (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex!("221704949b1ce1ab8dd174dc9b8c56fcffa27179569ce9219c0c2fe183d3d23343a4c42a0e2e9d6b9d0feb1df3883ec489b6671d1fa64089"), hex!("ebdecfdc87142d1a919034bf22ecfad934c9a85effff14b594ae2c00943ca62a39d6ee3be9df0bb504ce8a9e1669bc6959c42ad6a1d3b686")),
        ];

        for (msg, x, y) in MSGS {
            let p = hash2curve::encode_from_bytes::<Ed448, ExpandMsgXof<sha3::Shake256>>(
                &[msg],
                &[DST],
            )
            .unwrap();
            assert_eq!(p.is_on_curve().unwrap_u8(), 1u8);
            let p = p.to_affine();
            let mut xx = [0u8; 56];
            xx.copy_from_slice(&x[..]);
            xx.reverse();
            let mut yy = [0u8; 56];
            yy.copy_from_slice(&y[..]);
            yy.reverse();
            assert_eq!(p.x.to_bytes(), xx);
            assert_eq!(p.y.to_bytes(), yy);
        }
    }

    // TODO: uncomment once elliptic-curve-tools is updated to match elliptic-curve 0.14
    // #[test]
    // fn test_sum_of_products() {
    //     use elliptic_curve_tools::SumOfProducts;
    //     let values = [
    //         (Scalar::from(8u8), EdwardsPoint::GENERATOR),
    //         (Scalar::from(9u8), EdwardsPoint::GENERATOR),
    //         (Scalar::from(10u8), EdwardsPoint::GENERATOR),
    //         (Scalar::from(11u8), EdwardsPoint::GENERATOR),
    //         (Scalar::from(12u8), EdwardsPoint::GENERATOR),
    //     ];
    //
    //     let expected = EdwardsPoint::GENERATOR * Scalar::from(50u8);
    //     let result = EdwardsPoint::sum_of_products(&values);
    //     assert_eq!(result, expected);
    // }
    //
    // #[test]
    // fn test_sum_of_products2() {
    //     use elliptic_curve_tools::SumOfProducts;
    //     use rand_core::SeedableRng;
    //
    //     const TESTS: usize = 5;
    //     const CHUNKS: usize = 10;
    //     let mut rng = chacha20::ChaCha8Rng::from_seed([3u8; 32]);
    //
    //     for _ in 0..TESTS {
    //         let scalars = (0..CHUNKS)
    //             .map(|_| Scalar::random(&mut rng))
    //             .collect::<Vec<_>>();
    //         let points = (0..CHUNKS)
    //             .map(|_| EdwardsPoint::random(&mut rng))
    //             .collect::<Vec<_>>();
    //
    //         let input = scalars
    //             .iter()
    //             .zip(points.iter())
    //             .map(|(&s, &p)| (s, p))
    //             .collect::<Vec<_>>();
    //         let rhs = EdwardsPoint::sum_of_products(&input);
    //
    //         let expected = points
    //             .iter()
    //             .zip(scalars.iter())
    //             .fold(EdwardsPoint::IDENTITY, |acc, (&p, &s)| acc + (p * s));
    //
    //         assert_eq!(rhs, expected);
    //     }
    // }

    #[test]
    fn test_pow_add_mul() {
        use rand_core::SeedableRng;

        let mut rng = chacha20::ChaCha8Rng::seed_from_u64(0);
        let x = EdwardsScalar::random(&mut rng);
        let b = EdwardsScalar::random(&mut rng);

        let g1 = EdwardsPoint::GENERATOR;
        let g2 = Ed448::hash_from_bytes(b"test_pow_add_mul", b"test DST").unwrap();

        let expected_commitment = g1 * x + g2 * b;

        let shift = EdwardsScalar::from(256u16);
        let x_bytes = x.to_bytes_rfc_8032();
        let mut sum = EdwardsScalar::ZERO;
        let mut components = [EdwardsPoint::IDENTITY; 57];
        for i in 1..57 {
            let r = EdwardsScalar::random(&mut rng);
            sum += r * shift.pow([i as u64]);
            components[i] = g1 * EdwardsScalar::from(x_bytes[i]) + g2 * r;
        }
        components[0] = g1 * EdwardsScalar::from(x_bytes[0]) + g2 * (b - sum);

        let mut computed_commitment = EdwardsPoint::IDENTITY;
        for i in (0..57).rev() {
            computed_commitment *= shift;
            computed_commitment += components[i];
        }

        assert_eq!(computed_commitment, expected_commitment);
    }

    #[test]
    fn batch_normalize() {
        let points: [EdwardsPoint; 2] = [
            EdwardsPoint::try_from_rng(&mut SysRng).unwrap(),
            EdwardsPoint::try_from_rng(&mut SysRng).unwrap(),
        ];

        let affine_points = <EdwardsPoint as BatchNormalize<_>>::batch_normalize(&points);

        for (point, affine_point) in points.into_iter().zip(affine_points) {
            assert_eq!(affine_point, point.to_affine());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn batch_normalize_alloc() {
        let points = alloc::vec![
            EdwardsPoint::try_from_rng(&mut SysRng).unwrap(),
            EdwardsPoint::try_from_rng(&mut SysRng).unwrap(),
        ];

        let affine_points = <EdwardsPoint as BatchNormalize<_>>::batch_normalize(points.as_slice());

        for (point, affine_point) in points.into_iter().zip(affine_points) {
            assert_eq!(affine_point, point.to_affine());
        }
    }

    #[property_test]
    fn fuzz_is_torsion_free(bytes: [u8; 57]) {
        let scalar = EdwardsScalar::from_bytes_mod_order(&bytes.into());
        let mut point = EdwardsPoint::mul_by_generator(&scalar);
        prop_assert_eq!(point.is_torsion_free().unwrap_u8(), 1);

        let T4 = CompressedEdwardsY([0u8; 57])
            .decompress_unchecked()
            .unwrap();

        for _ in 0..3 {
            point += T4;
            assert!(bool::from(!point.is_torsion_free()));
        }
    }
}
