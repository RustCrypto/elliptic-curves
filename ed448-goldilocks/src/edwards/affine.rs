use crate::field::FieldElement;
use crate::*;
use core::fmt::{Display, Formatter, LowerHex, Result as FmtResult, UpperHex};
use core::ops::Mul;
use elliptic_curve::{Error, Generate, ctutils, point::NonIdentity, zeroize::DefaultIsZeroes};
use rand_core::{TryCryptoRng, TryRng};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Affine point on untwisted curve
#[derive(Copy, Clone, Debug)]
pub struct AffinePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
}

impl AffinePoint {
    /// The identity point
    pub const IDENTITY: AffinePoint = AffinePoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
    };

    /// Standard compression; store Y and sign of X
    pub fn compress(&self) -> CompressedEdwardsY {
        let affine_x = self.x;
        let affine_y = self.y;

        let mut compressed_bytes = [0u8; 57];

        let sign = affine_x.is_negative().unwrap_u8();

        let y_bytes = affine_y.to_bytes();
        compressed_bytes[..y_bytes.len()].copy_from_slice(&y_bytes[..]);
        *compressed_bytes.last_mut().expect("at least one byte") = sign << 7;
        CompressedEdwardsY(compressed_bytes)
    }

    /// Check if this point is on the curve
    pub fn is_on_curve(&self) -> Choice {
        // X^2 + Y^2 == 1 + D * X^2 * Y^2

        let XX = self.x.square();
        let YY = self.y.square();
        let lhs = YY + XX;
        let rhs = FieldElement::ONE + FieldElement::EDWARDS_D * XX * YY;

        lhs.ct_eq(&rhs)
    }

    /// Convert to edwards extended point
    pub fn to_edwards(&self) -> EdwardsPoint {
        EdwardsPoint {
            X: self.x,
            Y: self.y,
            Z: FieldElement::ONE,
            T: self.x * self.y,
        }
    }

    /// The X coordinate
    pub fn x(&self) -> [u8; 56] {
        self.x.to_bytes()
    }

    /// The Y coordinate
    pub fn y(&self) -> [u8; 56] {
        self.y.to_bytes()
    }

    pub(crate) fn isogeny(&self) -> Self {
        let x = self.x;
        let y = self.y;
        let mut t0 = x.square(); // x^2
        let t1 = t0 + FieldElement::ONE; // x^2+1
        t0 -= FieldElement::ONE; // x^2-1
        let mut t2 = y.square(); // y^2
        t2 = t2.double(); // 2y^2
        let t3 = x.double(); // 2x

        let mut t4 = t0 * y; // y(x^2-1)
        t4 = t4.double(); // 2y(x^2-1)
        let xNum = t4.double(); // xNum = 4y(x^2-1)

        let mut t5 = t0.square(); // x^4-2x^2+1
        t4 = t5 + t2; // x^4-2x^2+1+2y^2
        let xDen = t4 + t2; // xDen = x^4-2x^2+1+4y^2

        t5 *= x; // x^5-2x^3+x
        t4 = t2 * t3; // 4xy^2
        let yNum = t4 - t5; // yNum = -(x^5-2x^3+x-4xy^2)

        t4 = t1 * t2; // 2x^2y^2+2y^2
        let yDen = t5 - t4; // yDen = x^5-2x^3+x-2x^2y^2-2y^2

        Self {
            x: xNum * xDen.invert(),
            y: yNum * yDen.invert(),
        }
    }

    /// Generate a random [`AffinePoint`].
    ///
    /// Helper method that has `TryRng` bounds so `ProjectivePoint` can call it for its `group`
    /// impls, otherwise end users should use the `Generate` trait.
    pub(crate) fn try_from_rng<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryRng + ?Sized,
    {
        let mut bytes = CompressedEdwardsY::default();

        loop {
            rng.try_fill_bytes(&mut bytes.0)?;
            if let Some(point) = bytes.decompress().into() {
                return Ok(point);
            }
        }
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl ctutils::CtEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> ctutils::Choice {
        (self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)).into()
    }
}

impl ctutils::CtSelect for AffinePoint {
    fn ct_select(&self, other: &Self, choice: ctutils::Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&self.x, &other.x, choice.into()),
            y: FieldElement::conditional_select(&self.y, &other.y, choice.into()),
        }
    }
}

impl Eq for AffinePoint {}
impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Generate for AffinePoint {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Self::try_from_rng(rng)
    }
}

impl elliptic_curve::point::AffineCoordinates for AffinePoint {
    type FieldRepr = Ed448FieldBytes;

    fn from_coordinates(x: &Self::FieldRepr, y: &Self::FieldRepr) -> CtOption<Self> {
        let point = Self {
            x: FieldElement::from_bytes_extended(&x.0),
            y: FieldElement::from_bytes_extended(&y.0),
        };

        CtOption::new(point, point.is_on_curve())
    }

    fn x(&self) -> Self::FieldRepr {
        Ed448FieldBytes::from(self.x.to_bytes_extended())
    }

    fn y(&self) -> Self::FieldRepr {
        Ed448FieldBytes::from(self.y.to_bytes_extended())
    }

    fn x_is_odd(&self) -> Choice {
        self.x.is_negative()
    }

    fn y_is_odd(&self) -> Choice {
        self.y.is_negative()
    }
}

impl DefaultIsZeroes for AffinePoint {}

impl From<NonIdentity<AffinePoint>> for AffinePoint {
    fn from(affine: NonIdentity<AffinePoint>) -> Self {
        affine.to_point()
    }
}

impl TryFrom<AffinePoint> for NonIdentity<AffinePoint> {
    type Error = Error;

    fn try_from(affine_point: AffinePoint) -> Result<Self, Error> {
        NonIdentity::new(affine_point).into_option().ok_or(Error)
    }
}

impl Mul<&EdwardsScalar> for &AffinePoint {
    type Output = EdwardsPoint;

    #[inline]
    fn mul(self, scalar: &EdwardsScalar) -> Self::Output {
        self.to_edwards() * scalar
    }
}

define_mul_variants!(
    LHS = AffinePoint,
    RHS = EdwardsScalar,
    Output = EdwardsPoint
);

/// The compressed internal representation of a point on the Twisted Edwards Curve
pub type PointBytes = [u8; 57];

/// Represents a point on the Compressed Twisted Edwards Curve
/// in little endian format where the most significant bit is the sign bit
/// and the remaining 448 bits represent the y-coordinate
#[derive(Copy, Clone, Debug)]
pub struct CompressedEdwardsY(pub PointBytes);

impl elliptic_curve::zeroize::Zeroize for CompressedEdwardsY {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Display for CompressedEdwardsY {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for b in &self.0[..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl LowerHex for CompressedEdwardsY {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for b in &self.0[..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl UpperHex for CompressedEdwardsY {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        for b in &self.0[..] {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl Default for CompressedEdwardsY {
    fn default() -> Self {
        Self([0u8; 57])
    }
}

impl ConditionallySelectable for CompressedEdwardsY {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 57];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        Self(bytes)
    }
}

impl ConstantTimeEq for CompressedEdwardsY {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for CompressedEdwardsY {
    fn eq(&self, other: &CompressedEdwardsY) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for CompressedEdwardsY {}

impl AsRef<[u8]> for CompressedEdwardsY {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsRef<PointBytes> for CompressedEdwardsY {
    fn as_ref(&self) -> &PointBytes {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl From<CompressedEdwardsY> for Vec<u8> {
    fn from(value: CompressedEdwardsY) -> Self {
        Self::from(&value)
    }
}

#[cfg(feature = "alloc")]
impl From<&CompressedEdwardsY> for Vec<u8> {
    fn from(value: &CompressedEdwardsY) -> Self {
        value.0.to_vec()
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Vec<u8>> for CompressedEdwardsY {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<&Vec<u8>> for CompressedEdwardsY {
    type Error = &'static str;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for CompressedEdwardsY {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <PointBytes>::try_from(value).map_err(|_| "Invalid length")?;
        Ok(CompressedEdwardsY(bytes))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Box<[u8]>> for CompressedEdwardsY {
    type Error = &'static str;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl From<CompressedEdwardsY> for PointBytes {
    fn from(value: CompressedEdwardsY) -> Self {
        value.0
    }
}

impl From<&CompressedEdwardsY> for PointBytes {
    fn from(value: &CompressedEdwardsY) -> Self {
        Self::from(*value)
    }
}

#[cfg(feature = "serde")]
impl serdect::serde::Serialize for CompressedEdwardsY {
    fn serialize<S: serdect::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.0, s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serdect::serde::Deserialize<'de> for CompressedEdwardsY {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let mut arr = [0u8; 57];
        serdect::array::deserialize_hex_or_bin(&mut arr, d)?;
        Ok(CompressedEdwardsY(arr))
    }
}

impl From<PointBytes> for CompressedEdwardsY {
    fn from(point: PointBytes) -> Self {
        Self(point)
    }
}

impl CompressedEdwardsY {
    /// The compressed generator point
    pub const GENERATOR: Self = Self([
        20, 250, 48, 242, 91, 121, 8, 152, 173, 200, 215, 78, 44, 19, 189, 253, 196, 57, 124, 230,
        28, 255, 211, 58, 215, 194, 160, 5, 30, 156, 120, 135, 64, 152, 163, 108, 115, 115, 234,
        75, 98, 199, 201, 86, 55, 32, 118, 136, 36, 188, 182, 110, 113, 70, 63, 105, 0,
    ]);
    /// The compressed identity point
    pub const IDENTITY: Self = Self([0u8; 57]);

    /// Attempt to decompress to an `AffinePoint`.
    ///
    /// Returns `None` if the input is not the \\(y\\)-coordinate of a
    /// curve point.
    pub fn decompress_unchecked(&self) -> CtOption<AffinePoint> {
        // Safe to unwrap here as the underlying data structure is a slice
        let (sign, b) = self.0.split_last().expect("slice is non-empty");

        let mut y_bytes: [u8; 56] = [0; 56];
        y_bytes.copy_from_slice(b);

        // Recover x using y
        let y = FieldElement::from_bytes(&y_bytes);
        let yy = y.square();
        let dyy = FieldElement::EDWARDS_D * yy;
        let numerator = FieldElement::ONE - yy;
        let denominator = FieldElement::ONE - dyy;

        let (mut x, is_res) = FieldElement::sqrt_ratio(&numerator, &denominator);

        // Compute correct sign of x
        let compressed_sign_bit = Choice::from(sign >> 7);
        let is_negative = x.is_negative();
        x.conditional_negate(compressed_sign_bit ^ is_negative);

        CtOption::new(AffinePoint { x, y }, is_res)
    }

    /// Attempt to decompress to an `AffinePoint`.
    ///
    /// Returns `None`:
    /// - if the input is not the \\(y\\)-coordinate of a curve point.
    /// - if the input point is not on the curve.
    /// - if the input point has nonzero torsion component.
    pub fn decompress(&self) -> CtOption<AffinePoint> {
        self.decompress_unchecked()
            .and_then(|pt| CtOption::new(pt, pt.is_on_curve() & pt.to_edwards().is_torsion_free()))
    }

    /// View this `CompressedEdwardsY` as an array of bytes.
    pub const fn as_bytes(&self) -> &PointBytes {
        &self.0
    }

    /// Copy this `CompressedEdwardsY` to an array of bytes.
    pub const fn to_bytes(&self) -> PointBytes {
        self.0
    }
}
