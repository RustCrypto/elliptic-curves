use core::fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use super::ConstMontyType;
use crate::{
    AffinePoint, Decaf448, DecafPoint, Ed448, EdwardsPoint,
    curve::twedwards::extended::ExtendedPoint as TwistedExtendedPoint,
};
use elliptic_curve::{
    array::Array,
    bigint::{
        Integer, NonZero, U448, U704,
        consts::{U56, U84, U88},
    },
    group::cofactor::CofactorGroup,
    zeroize::DefaultIsZeroes,
};
use hash2curve::{FromOkm, MapToCurve};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

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

impl FromOkm for Ed448FieldElement {
    type Length = U84;

    fn from_okm(data: &Array<u8, Self::Length>) -> Self {
        const SEMI_WIDE_MODULUS: NonZero<U704> = NonZero::<U704>::new_unwrap(U704::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ));
        let mut tmp = Array::<u8, U88>::default();
        tmp[4..].copy_from_slice(&data[..]);

        let mut num = U704::from_be_slice(&tmp[..]);
        num %= SEMI_WIDE_MODULUS;

        let bytes =
            <[u8; 56]>::try_from(&num.to_le_bytes()[..56]).expect("slice is the wrong length");
        Self(FieldElement(ConstMontyType::new(&U448::from_le_slice(
            &bytes,
        ))))
    }
}

impl FromOkm for Decaf448FieldElement {
    type Length = U56;

    fn from_okm(data: &Array<u8, Self::Length>) -> Self {
        Self(FieldElement::from_bytes(&data.0))
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

#[derive(Clone, Copy, Default, Debug)]
pub struct Ed448FieldElement(FieldElement);

impl MapToCurve for Ed448 {
    type CurvePoint = EdwardsPoint;
    type FieldElement = Ed448FieldElement;

    fn map_to_curve(element: Ed448FieldElement) -> Self::CurvePoint {
        element.0.map_to_curve_elligator2().isogeny().to_edwards()
    }

    fn map_to_subgroup(point: EdwardsPoint) -> EdwardsPoint {
        point.clear_cofactor()
    }

    fn add_and_map_to_subgroup(lhs: EdwardsPoint, rhs: EdwardsPoint) -> EdwardsPoint {
        (lhs + rhs).clear_cofactor()
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Decaf448FieldElement(FieldElement);

impl MapToCurve for Decaf448 {
    type CurvePoint = DecafPoint;
    type FieldElement = Decaf448FieldElement;

    fn map_to_curve(element: Decaf448FieldElement) -> DecafPoint {
        DecafPoint(element.0.map_to_curve_decaf448())
    }

    fn map_to_subgroup(point: DecafPoint) -> DecafPoint {
        point
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

    pub fn is_negative(&self) -> Choice {
        self.0.retrieve().is_odd()
    }

    /// Inverts a field element
    /// Previous chain length: 462, new length 460
    pub fn invert(&self) -> Self {
        const INV_EXP: U448 = U448::from_be_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffd",
        );
        Self(self.0.pow(&INV_EXP))
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

    pub(crate) fn map_to_curve_elligator2(&self) -> AffinePoint {
        let mut t1 = self.square(); // 1.   t1 = u^2
        t1 *= Self::Z; // 2.   t1 = Z * t1              // Z * u^2
        let e1 = t1.ct_eq(&Self::MINUS_ONE); // 3.   e1 = t1 == -1            // exceptional case: Z * u^2 == -1
        t1.conditional_assign(&Self::ZERO, e1); // 4.   t1 = CMOV(t1, 0, e1)     // if t1 == -1, set t1 = 0
        let mut x1 = t1 + Self::ONE; // 5.   x1 = t1 + 1
        x1 = x1.invert(); // 6.   x1 = inv0(x1)
        x1 *= -Self::J; // 7.   x1 = -A * x1             // x1 = -A / (1 + Z * u^2)
        let mut gx1 = x1 + Self::J; // 8.  gx1 = x1 + A
        gx1 *= x1; // 9.  gx1 = gx1 * x1
        gx1 += Self::ONE; // 10. gx1 = gx1 + B
        gx1 *= x1; // 11. gx1 = gx1 * x1            // gx1 = x1^3 + A * x1^2 + B * x1
        let x2 = -x1 - Self::J; // 12.  x2 = -x1 - A
        let gx2 = t1 * gx1; // 13. gx2 = t1 * gx1
        let e2 = gx1.is_square(); // 14.  e2 = is_square(gx1)
        let x = Self::conditional_select(&x2, &x1, e2); // 15.   x = CMOV(x2, x1, e2)    // If is_square(gx1), x = x1, else x = x2
        let y2 = Self::conditional_select(&gx2, &gx1, e2); // 16.  y2 = CMOV(gx2, gx1, e2)  // If is_square(gx1), y2 = gx1, else y2 = gx2
        let mut y = y2.sqrt(); // 17.   y = sqrt(y2)
        let e3 = y.is_negative(); // 18.  e3 = sgn0(y) == 1
        y.conditional_negate(e2 ^ e3); //       y = CMOV(-y, y, e2 xor e3)
        AffinePoint { x, y }
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
            expander.fill_bytes(&mut data);
            // TODO: This should be `Curve448FieldElement`.
            let u0 = Ed448FieldElement::from_okm(&data).0;
            let mut e_u0 = *expected_u0;
            e_u0.reverse();
            let mut e_u1 = *expected_u1;
            e_u1.reverse();
            assert_eq!(u0.to_bytes(), e_u0);
            expander.fill_bytes(&mut data);
            // TODO: This should be `Curve448FieldElement`.
            let u1 = Ed448FieldElement::from_okm(&data).0;
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
            expander.fill_bytes(&mut data);
            let u0 = Ed448FieldElement::from_okm(&data).0;
            let mut e_u0 = *expected_u0;
            e_u0.reverse();
            let mut e_u1 = *expected_u1;
            e_u1.reverse();
            assert_eq!(u0.to_bytes(), e_u0);
            expander.fill_bytes(&mut data);
            let u1 = Ed448FieldElement::from_okm(&data).0;
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
