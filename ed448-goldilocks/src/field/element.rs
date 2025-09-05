use core::fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use super::{ConstMontyType, MODULUS};
use crate::{
    Decaf448, DecafPoint, Ed448, EdwardsPoint,
    curve::twedwards::extended::ExtendedPoint as TwistedExtendedPoint,
};
use elliptic_curve::ops::Reduce;
use elliptic_curve::{
    Field,
    array::Array,
    bigint::{
        Integer, NonZero, U448, U704, Zero,
        consts::{U56, U64, U84, U88},
        modular::ConstMontyParams,
    },
    zeroize::DefaultIsZeroes,
};
use hash2curve::MapToCurve;
use rand_core::TryRngCore;
use subtle::{
    Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess,
    CtOption,
};

#[derive(Clone, Copy, Default)]
pub struct FieldElement(pub(crate) ConstMontyType);

impl Display for FieldElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0.retrieve())
    }
}

impl Debug for FieldElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({:x})", self.0.retrieve())
    }
}

impl LowerHex for FieldElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0.retrieve())
    }
}

impl UpperHex for FieldElement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0.retrieve())
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ConstMontyType::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for FieldElement {}

impl Reduce<Array<u8, U84>> for FieldElement {
    fn reduce(value: &Array<u8, U84>) -> Self {
        const SEMI_WIDE_MODULUS: NonZero<U704> = NonZero::<U704>::new_unwrap(U704::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ));
        let mut tmp = Array::<u8, U88>::default();
        tmp[4..].copy_from_slice(&value[..]);

        let mut num = U704::from_be_slice(&tmp[..]);
        num %= SEMI_WIDE_MODULUS;

        let bytes =
            <[u8; 56]>::try_from(&num.to_le_bytes()[..56]).expect("slice is the wrong length");
        FieldElement(ConstMontyType::new(&U448::from_le_slice(&bytes)))
    }
}

impl Reduce<Array<u8, U56>> for FieldElement {
    fn reduce(value: &Array<u8, U56>) -> Self {
        FieldElement::from_bytes(&value.0)
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.add(&other.0))
    }
}

define_add_variants!(
    LHS = FieldElement,
    RHS = FieldElement,
    Output = FieldElement
);

impl AddAssign for FieldElement {
    fn add_assign(&mut self, other: FieldElement) {
        *self = *self + other;
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &FieldElement) {
        *self = *self + *other;
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.sub(&other.0))
    }
}

define_sub_variants!(
    LHS = FieldElement,
    RHS = FieldElement,
    Output = FieldElement
);

impl SubAssign for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        *self = *self - other;
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = *self - *other;
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.mul(&other.0))
    }
}

define_mul_variants!(
    LHS = FieldElement,
    RHS = FieldElement,
    Output = FieldElement
);

impl MulAssign<&FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: &FieldElement) {
        *self = *self * *other;
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, other: FieldElement) {
        *self = *self * other;
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        -*self
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        Self(self.0.neg())
    }
}

impl MapToCurve for Ed448 {
    type FieldElement = FieldElement;
    type FieldLength = U84;
    type ScalarLength = U84;

    fn map_to_curve(element: FieldElement) -> EdwardsPoint {
        element.map_to_curve_elligator2_edwards448()
    }
}

impl MapToCurve for Decaf448 {
    type FieldElement = FieldElement;
    type FieldLength = U56;
    type ScalarLength = U64;

    fn map_to_curve(element: FieldElement) -> DecafPoint {
        DecafPoint(element.map_to_curve_decaf448())
    }
}

impl Sum for FieldElement {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for FieldElement {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Mul::mul).unwrap_or(Self::ONE)
    }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().product()
    }
}

impl Field for FieldElement {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn try_from_rng<R: TryRngCore + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut bytes = [0; 56];

        loop {
            rng.try_fill_bytes(&mut bytes)?;
            if let Some(fe) = Self::from_repr(&bytes).into() {
                return Ok(fe);
            }
        }
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::from(self.0.invert()).map(Self)
    }

    fn sqrt(&self) -> CtOption<Self> {
        let sqrt = self.sqrt();
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (result, is_square) = Self::sqrt_ratio(num, div);
        (is_square, result)
    }
}

impl FieldElement {
    pub const A_PLUS_TWO_OVER_FOUR: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000098aa",
    )));
    pub const DECAF_FACTOR: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "22d962fbeb24f7683bf68d722fa26aa0a1f1a7b8a5b8d54b64a2d780968c14ba839a66f4fd6eded260337bf6aa20ce529642ef0f45572736",
    )));
    pub const EDWARDS_D: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756",
    )));
    pub const J: Self = Self(ConstMontyType::new(&U448::from_u64(156326)));
    pub const MINUS_ONE: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    )));
    pub const NEG_EDWARDS_D: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000098a9",
    )));
    pub const NEG_FOUR_TIMES_TWISTED_D: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000262a8",
    )));
    pub const ONE: Self = Self(ConstMontyType::new(&U448::ONE));
    pub const TWO: Self = Self(ConstMontyType::new(&U448::from_u64(2)));
    pub const TWISTED_D: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6755",
    )));
    pub const TWO_TIMES_TWISTED_D: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffeceab",
    )));
    pub const Z: Self = Self(ConstMontyType::new(&U448::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    )));
    pub const ZERO: Self = Self(ConstMontyType::new(&U448::ZERO));
    // See https://www.rfc-editor.org/rfc/rfc9380.html#name-curve448-q-3-mod-4-k-1.
    // 1. c1 = (q - 3) / 4         # Integer arithmetic
    const C1: U448 = U448::from_be_hex(
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );

    pub fn is_negative(&self) -> Choice {
        self.0.retrieve().is_odd()
    }

    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Inverts a field element
    pub fn invert(&self) -> Self {
        Self(self.0.invert().unwrap_or(ConstMontyType::default()))
    }

    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Squares a field element  `n` times
    fn square_n<const N: u32>(&self) -> FieldElement {
        let mut result = *self;

        for _ in 0..N {
            result = result.square();
        }

        result
    }

    pub fn is_square(&self) -> Choice {
        const IS_SQUARE_EXP: U448 = U448::from_le_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        );
        self.0.pow(&IS_SQUARE_EXP).ct_eq(&FieldElement::ONE.0)
    }

    pub fn sqrt(&self) -> FieldElement {
        const SQRT_EXP: U448 = U448::from_be_hex(
            "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000000000000000000000000000000000000000",
        );
        Self(self.0.pow(&SQRT_EXP))
    }

    pub fn to_bytes(self) -> [u8; 56] {
        let mut bytes = [0u8; 56];
        bytes.copy_from_slice(&self.0.retrieve().to_le_bytes()[..56]);
        bytes
    }

    pub fn to_bytes_extended(self) -> [u8; 57] {
        let mut bytes = [0u8; 57];
        bytes[..56].copy_from_slice(&self.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 56]) -> Self {
        Self(ConstMontyType::new(&U448::from_le_slice(bytes)))
    }

    pub fn from_bytes_extended(bytes: &[u8; 57]) -> Self {
        Self(ConstMontyType::new(&U448::from_le_slice(&bytes[..56])))
    }

    pub fn from_repr(bytes: &[u8; 56]) -> CtOption<Self> {
        let integer = U448::from_le_slice(bytes);
        let is_some = integer.ct_lt(MODULUS::PARAMS.modulus());
        CtOption::new(Self(ConstMontyType::new(&integer)), is_some)
    }

    pub fn double(&self) -> Self {
        Self(self.0.double())
    }

    /// Computes the inverse square root of a field element
    /// Returns the result and a boolean to indicate whether self
    /// was a Quadratic residue
    pub(crate) fn inverse_square_root(&self) -> (FieldElement, Choice) {
        let (mut l0, mut l1, mut l2);

        l1 = self.square();
        l2 = l1 * self;
        l1 = l2.square();
        l2 = l1 * self;
        l1 = l2.square_n::<3>();
        l0 = l2 * l1;
        l1 = l0.square_n::<3>();
        l0 = l2 * l1;
        l2 = l0.square_n::<9>();
        l1 = l0 * l2;
        l0 = l1.square();
        l2 = l0 * self;
        l0 = l2.square_n::<18>();
        l2 = l1 * l0;
        l0 = l2.square_n::<37>();
        l1 = l2 * l0;
        l0 = l1.square_n::<37>();
        l1 = l2 * l0;
        l0 = l1.square_n::<111>();
        l2 = l1 * l0;
        l0 = l2.square();
        l1 = l0 * self;
        l0 = l1.square_n::<223>();
        l1 = l2 * l0;
        l2 = l1.square();
        l0 = l2 * self;

        let is_residue = l0.ct_eq(&FieldElement::ONE);
        (l1, is_residue)
    }

    /// Computes the square root ratio of two elements
    pub(crate) fn sqrt_ratio(u: &FieldElement, v: &FieldElement) -> (FieldElement, Choice) {
        // Compute sqrt(1/(uv))
        let x = *u * v;
        let (inv_sqrt_x, is_res) = x.inverse_square_root();
        // Return u * sqrt(1/(uv)) == sqrt(u/v). However, since this trick only works
        // for u != 0, check for that case explicitly (when u == 0 then inv_sqrt_x
        // will be zero, which is what we want, but is_res will be 0)
        let zero_u = u.ct_eq(&FieldElement::ZERO);
        (inv_sqrt_x * u, zero_u | is_res)
    }

    pub(crate) fn div_by_2(&self) -> FieldElement {
        Self(self.0.div_by_2())
    }

    // See https://www.rfc-editor.org/rfc/rfc9380.html#name-curve448-q-3-mod-4-k-1.
    pub(crate) fn map_to_curve_elligator2_curve448(
        &self,
    ) -> (FieldElement, FieldElement, FieldElement) {
        // 1.  tv1 = u^2
        let mut tv1 = self.square();
        // 2.   e1 = tv1 == 1
        let e1 = tv1.ct_eq(&FieldElement::ONE);
        // 3.  tv1 = CMOV(tv1, 0, e1)  # If Z * u^2 == -1, set tv1 = 0
        tv1.conditional_assign(&FieldElement::ZERO, e1);
        // 4.   xd = 1 - tv1
        let xd = FieldElement::ONE - tv1;
        // 5.  x1n = -J
        let x1n = -Self::J;
        // 6.  tv2 = xd^2
        let tv2 = xd.square();
        // 7.  gxd = tv2 * xd          # gxd = xd^3
        let gxd = tv2 * xd;
        // 8.  gx1 = -J * tv1          # x1n + J * xd
        let mut gx1 = x1n * tv1;
        // 9.  gx1 = gx1 * x1n         # x1n^2 + J * x1n * xd
        gx1 *= x1n;
        // 10. gx1 = gx1 + tv2         # x1n^2 + J * x1n * xd + xd^2
        gx1 += tv2;
        // 11. gx1 = gx1 * x1n         # x1n^3 + J * x1n^2 * xd + x1n * xd^2
        gx1 *= x1n;
        // 12. tv3 = gxd^2
        let tv3 = gxd.square();
        // 13. tv2 = gx1 * gxd         # gx1 * gxd
        let tv2 = gx1 * gxd;
        // 14. tv3 = tv3 * tv2         # gx1 * gxd^3
        let tv3 = tv3 * tv2;
        // 15.  y1 = tv3^c1            # (gx1 * gxd^3)^((p - 3) / 4)
        let mut y1 = FieldElement(tv3.0.pow(&Self::C1));
        // 16.  y1 = y1 * tv2          # gx1 * gxd * (gx1 * gxd^3)^((p - 3) / 4)
        y1 *= tv2;
        // 17. x2n = -tv1 * x1n        # x2 = x2n / xd = -1 * u^2 * x1n / xd
        let x2n = -tv1 * x1n;
        // 18.  y2 = y1 * u
        let mut y2 = y1 * self;
        // 19.  y2 = CMOV(y2, 0, e1)
        y2.conditional_assign(&FieldElement::ZERO, e1);
        // 20. tv2 = y1^2
        let mut tv2 = y1.square();
        // 21. tv2 = tv2 * gxd
        tv2 *= gxd;
        // 22.  e2 = tv2 == gx1
        let e2 = tv2.ct_eq(&gx1);
        // 23.  xn = CMOV(x2n, x1n, e2)  # If e2, x = x1, else x = x2
        let xn = FieldElement::conditional_select(&x2n, &x1n, e2);
        // 24.   y = CMOV(y2, y1, e2)    # If e2, y = y1, else y = y2
        let mut y = FieldElement::conditional_select(&y2, &y1, e2);
        // 25.  e3 = sgn0(y) == 1        # Fix sign of y
        let e3 = y.is_negative();
        // 26.   y = CMOV(y, -y, e2 XOR e3)
        y.conditional_negate(e2 ^ e3);
        // 27. return (xn, xd, y, 1)

        (xn, xd, y)
    }

    fn map_to_curve_elligator2_edwards448(&self) -> EdwardsPoint {
        // 1. (xn, xd, yn, yd) = map_to_curve_elligator2_curve448(u)
        let (xn, xd, yn) = self.map_to_curve_elligator2_curve448();
        // 2.  xn2 = xn^2
        let xn2 = xn.square();
        // 3.  xd2 = xd^2
        let xd2 = xd.square();
        // 4.  xd4 = xd2^2
        let xd4 = xd2.square();
        // 5.  yn2 = yn^2
        let yn2 = yn.square();
        // 6.  yd2 = yd^2
        let yd2 = FieldElement::ONE;
        // 7.  xEn = xn2 - xd2
        let mut xEn = xn2 - xd2;
        // 8.  tv2 = xEn - xd2
        let mut tv2 = xEn - xd2;
        // 9.  xEn = xEn * xd2
        xEn *= xd2;
        // 10. xEn = xEn * yd
        // SKIP: yd = 1
        // 11. xEn = xEn * yn
        xEn *= yn;
        // 12. xEn = xEn * 4
        xEn = xEn.double().double();
        // 13. tv2 = tv2 * xn2
        tv2 *= xn2;
        // 14. tv2 = tv2 * yd2
        // SKIP: yd2 = 1
        // 15. tv3 = 4 * yn2
        let tv3 = yn2.double().double();
        // 16. tv1 = tv3 + yd2
        let mut tv1 = tv3 + yd2;
        // 17. tv1 = tv1 * xd4
        tv1 *= xd4;
        // 18. xEd = tv1 + tv2
        let mut xEd = tv1 + tv2;
        // 19. tv2 = tv2 * xn
        tv2 *= xn;
        // 20. tv4 = xn * xd4
        let tv4 = xn * xd4;
        // 21. yEn = tv3 - yd2
        let mut yEn = tv3 - yd2;
        // 22. yEn = yEn * tv4
        yEn *= tv4;
        // 23. yEn = yEn - tv2
        yEn -= tv2;
        // 24. tv1 = xn2 + xd2
        let mut tv1 = xn2 + xd2;
        // 25. tv1 = tv1 * xd2
        tv1 *= xd2;
        // 26. tv1 = tv1 * xd
        tv1 *= xd;
        // 27. tv1 = tv1 * yn2
        tv1 *= yn2;
        // 28. tv1 = -2 * tv1
        tv1 *= -FieldElement::TWO;
        // 29. yEd = tv2 + tv1
        let mut yEd = tv2 + tv1;
        // 30. tv4 = tv4 * yd2
        // SKIP: yd2 = 1
        // 31. yEd = yEd + tv4
        yEd += tv4;
        // 32. tv1 = xEd * yEd
        let tv1 = xEd * yEd;
        // 33.   e = tv1 == 0
        let e = tv1.ct_eq(&FieldElement::ZERO);
        // 34. xEn = CMOV(xEn, 0, e)
        xEn.conditional_assign(&FieldElement::ZERO, e);
        // 35. xEd = CMOV(xEd, 1, e)
        xEd.conditional_assign(&FieldElement::ONE, e);
        // 36. yEn = CMOV(yEn, 1, e)
        yEn.conditional_assign(&FieldElement::ONE, e);
        // 37. yEd = CMOV(yEd, 1, e)
        yEd.conditional_assign(&FieldElement::ONE, e);
        // 38. return (xEn, xEd, yEn, yEd)

        // Output: (xn, xd, yn, yd) such that (xn / xd, yn / yd) is a
        // point on edwards448.

        EdwardsPoint {
            X: xEn * yEd,
            Y: xEd * yEn,
            Z: xEd * yEd,
            T: xEn * yEn,
        }
    }

    // See https://www.shiftleft.org/papers/decaf/decaf.pdf#section.A.3.
    // Implementation copied from <https://sourceforge.net/p/ed448goldilocks/code/ci/e5cc6240690d3ffdfcbdb1e4e851954b789cd5d9/tree/src/per_curve/elligator.tmpl.c#l28>.
    pub(crate) fn map_to_curve_decaf448(&self) -> TwistedExtendedPoint {
        const ONE_MINUS_TWO_D: FieldElement =
            FieldElement(ConstMontyType::new(&U448::from_u64(78163)));

        let r = -self.square();

        let a = r - Self::ONE;
        let b = a * Self::EDWARDS_D;
        let a = b + Self::ONE;
        let b = b - r;
        let c = a * b;

        let a = r + Self::ONE;
        let n = a * ONE_MINUS_TWO_D;

        let a = c * n;
        let (b, square) = a.inverse_square_root();
        let c = Self::conditional_select(self, &Self::ONE, square);
        let e = b * c;

        let mut a = n * e;
        a.conditional_negate(!a.is_negative() ^ square);

        let c = e * ONE_MINUS_TWO_D;
        let b = c.square();
        let e = r - Self::ONE;
        let c = b * e;
        let mut b = c * n;
        b.conditional_negate(square);
        let b = b - Self::ONE;

        let c = a.square();
        let a = a.double();
        let e = c + Self::ONE;
        let T = a * e;
        let X = a * b;
        let a = Self::ONE - c;
        let Y = e * a;
        let Z = a * b;

        TwistedExtendedPoint { X, Y, Z, T }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::consts::U32;
    use hash2curve::{ExpandMsg, ExpandMsgXof, Expander};
    use hex_literal::hex;
    use sha3::Shake256;

    #[test]
    fn from_okm_curve448() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_RO_";
        const MSGS: &[(&[u8], [u8; 56], [u8; 56])] = &[
            (b"", hex!("c704c7b3d3b36614cf3eedd0324fe6fe7d1402c50efd16cff89ff63f50938506280d3843478c08e24f7842f4e3ef45f6e3c4897f9d976148"), hex!("c25427dc97fff7a5ad0a78654e2c6c27b1c1127b5b53c7950cd1fd6edd2703646b25f341e73deedfebf022d1d3cecd02b93b4d585ead3ed7")),
            (b"abc", hex!("2dd95593dfee26fe0d218d3d9a0a23d9e1a262fd1d0b602483d08415213e75e2db3c69b0a5bc89e71bcefc8c723d2b6a0cf263f02ad2aa70"), hex!("272e4c79a1290cc6d2bc4f4f9d31bf7fbe956ca303c04518f117d77c0e9d850796fc3e1e2bcb9c75e8eaaded5e150333cae9931868047c9d")),
            (b"abcdef0123456789", hex!("6aab71a38391639f27e49eae8b1cb6b7172a1f478190ece293957e7cdb2391e7cc1c4261970d9c1bbf9c3915438f74fbd7eb5cd4d4d17ace"), hex!("c80b8380ca47a3bcbf76caa75cef0e09f3d270d5ee8f676cde11aedf41aaca6741bd81a86232bd336ccb42efad39f06542bc06a67b65909e")),
            (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hex!("cb5c27e51f9c18ee8ffdb6be230f4eb4f2c2481963b2293484f08da2241c1ff59f80978e6defe9d70e34abba2fcbe12dc3a1eb2c5d3d2e4a"), hex!("c895e8afecec5466e126fa70fc4aa784b8009063afb10e3ee06a9b22318256aa8693b0c85b955cf2d6540b8ed71e729af1b8d5ca3b116cd7")),
            (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex!("8cba93a007bb2c801b1769e026b1fa1640b14a34cf3029db3c7fd6392745d6fec0f7870b5071d6da4402cedbbde28ae4e50ab30e1049a238"), hex!("4223746145069e4b8a981acc3404259d1a2c3ecfed5d864798a89d45f81a2c59e2d40eb1d5f0fe11478cbb2bb30246dd388cb932ad7bb330")),
        ];

        for (msg, expected_u0, expected_u1) in MSGS {
            let mut expander = <ExpandMsgXof<Shake256> as ExpandMsg<U32>>::expand_message(
                &[msg],
                &[DST],
                (84 * 2).try_into().unwrap(),
            )
            .unwrap();
            let mut data = Array::<u8, U84>::default();
            expander.fill_bytes(&mut data).unwrap();
            // TODO: This should be `Curve448FieldElement`.
            let u0 = FieldElement::reduce(&data);
            let mut e_u0 = *expected_u0;
            e_u0.reverse();
            let mut e_u1 = *expected_u1;
            e_u1.reverse();
            assert_eq!(u0.to_bytes(), e_u0);
            expander.fill_bytes(&mut data).unwrap();
            // TODO: This should be `Curve448FieldElement`.
            let u1 = FieldElement::reduce(&data);
            assert_eq!(u1.to_bytes(), e_u1);
        }
    }

    #[test]
    fn from_okm_edwards448() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_";
        const MSGS: &[(&[u8], [u8; 56], [u8; 56])] = &[
            (b"", hex!("0847c5ebf957d3370b1f98fde499fb3e659996d9fc9b5707176ade785ba72cd84b8a5597c12b1024be5f510fa5ba99642c4cec7f3f69d3e7"), hex!("f8cbd8a7ae8c8deed071f3ac4b93e7cfcb8f1eac1645d699fd6d3881cb295a5d3006d9449ed7cad412a77a1fe61e84a9e41d59ef384d6f9a")),
            (b"abc", hex!("04d975cd938ab49be3e81703d6a57cca84ed80d2ff6d4756d3f22947fb5b70ab0231f0087cbfb4b7cae73b41b0c9396b356a4831d9a14322"), hex!("2547ca887ac3db7b5fad3a098aa476e90078afe1358af6c63d677d6edfd2100bc004e0f5db94dd2560fc5b308e223241d00488c9ca6b0ef2")),
            (b"abcdef0123456789", hex!("10659ce25588db4e4be6f7c791a79eb21a7f24aaaca76a6ca3b83b80aaf95aa328fe7d569a1ac99f9cd216edf3915d72632f1a8b990e250c"), hex!("9243e5b6c480683fd533e81f4a778349a309ce00bd163a29eb9fa8dbc8f549242bef33e030db21cffacd408d2c4264b93e476c6a8590e7aa")),
            (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hex!("c80390020e578f009ead417029eff6cd0926110922db63ab98395e3bdfdd5d8a65b1a2b8d495dc8c5e59b7f3518731f7dfc0f93ace5dee4b"), hex!("1c4dc6653a445bbef2add81d8e90a6c8591a788deb91d0d3f1519a2e4a460313041b77c1b0817f2e80b388e5c3e49f37d787dc1f85e4324a")),
            (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex!("163c79ab0210a4b5e4f44fb19437ea965bf5431ab233ef16606f0b03c5f16a3feb7d46a5a675ce8f606e9c2bf74ee5336c54a1e54919f13f"), hex!("f99666bde4995c4088333d6c2734687e815f80a99c6da02c47df4b51f6c9d9ed466b4fecf7d9884990a8e0d0be6907fa437e0b1a27f49265")),
        ];

        for (msg, expected_u0, expected_u1) in MSGS {
            let mut expander = <ExpandMsgXof<Shake256> as ExpandMsg<U32>>::expand_message(
                &[msg],
                &[DST],
                (84 * 2).try_into().unwrap(),
            )
            .unwrap();
            let mut data = Array::<u8, U84>::default();
            expander.fill_bytes(&mut data).unwrap();
            let u0 = FieldElement::reduce(&data);
            let mut e_u0 = *expected_u0;
            e_u0.reverse();
            let mut e_u1 = *expected_u1;
            e_u1.reverse();
            assert_eq!(u0.to_bytes(), e_u0);
            expander.fill_bytes(&mut data).unwrap();
            let u1 = FieldElement::reduce(&data);
            assert_eq!(u1.to_bytes(), e_u1);
        }
    }

    #[test]
    fn get_constants() {
        let m1 = -FieldElement::ONE;
        assert_eq!(m1, FieldElement::MINUS_ONE);
    }

    #[test]
    fn sqrt() {
        let nine = FieldElement::from_bytes(&[
            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let three = FieldElement::from_bytes(&[
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(three, nine.sqrt());
    }
}
