use core::fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use elliptic_curve::{
    bigint::{
        consts::{U84, U88},
        Encoding, NonZero, U448, U704,
    },
    generic_array::GenericArray,
    hash2curve::{FromOkm, MapToCurve},
};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::DefaultIsZeroes;

use super::ResidueType;
use crate::curve::twedwards::extended::ExtendedPoint as TwistedExtendedPoint;
use crate::{AffinePoint, EdwardsPoint};

#[derive(Clone, Copy, Default)]
pub(crate) struct FieldElement(pub(crate) ResidueType);

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
        Self(ResidueType::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for FieldElement {}

impl FromOkm for FieldElement {
    type Length = U84;

    fn from_okm(data: &GenericArray<u8, Self::Length>) -> Self {
        const SEMI_WIDE_MODULUS: NonZero<U704> = NonZero::from_uint(U704::from_be_hex("0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        let mut tmp = GenericArray::<u8, U88>::default();
        tmp[4..].copy_from_slice(&data[..]);

        let mut num = U704::from_be_slice(&tmp[..]);
        num %= SEMI_WIDE_MODULUS;

        let bytes =
            <[u8; 56]>::try_from(&num.to_le_bytes()[..56]).expect("slice is the wrong length");
        FieldElement(ResidueType::new(&U448::from_le_slice(&bytes)))
    }
}

#[cfg(feature = "zeroize")]
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

impl MapToCurve for FieldElement {
    type Output = EdwardsPoint;

    fn map_to_curve(&self) -> Self::Output {
        self.map_to_curve_elligator2().to_edwards()
    }
}

impl FieldElement {
    pub const A_PLUS_TWO_OVER_FOUR: Self = Self(ResidueType::new(&U448::from_be_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000098aa")));
    pub const DECAF_FACTOR: Self = Self(ResidueType::new(&U448::from_be_hex("22d962fbeb24f7683bf68d722fa26aa0a1f1a7b8a5b8d54b64a2d780968c14ba839a66f4fd6eded260337bf6aa20ce529642ef0f45572736")));
    pub const EDWARDS_D: Self = Self(ResidueType::new(&U448::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756")));
    pub const J: Self = Self(ResidueType::new(&U448::from_u64(156326)));
    pub const MINUS_ONE: Self = Self(ResidueType::new(&U448::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe")));
    pub const NEG_EDWARDS_D: Self = Self(ResidueType::new(&U448::from_be_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000098a9")));
    pub const NEG_FOUR_TIMES_TWISTED_D: Self = Self(ResidueType::new(&U448::from_be_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000262a8")));
    pub const ONE: Self = Self(ResidueType::new(&U448::ONE));
    pub const TWISTED_D: Self = Self(ResidueType::new(&U448::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6755")));
    pub const TWO_TIMES_TWISTED_D: Self = Self(ResidueType::new(&U448::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffeceab")));
    pub const Z: Self = Self(ResidueType::new(&U448::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffe")));
    pub const ZERO: Self = Self(ResidueType::new(&U448::ZERO));

    pub fn is_negative(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[0] & 1).into()
    }

    /// Inverts a field element
    /// Previous chain length: 462, new length 460
    pub fn invert(&self) -> Self {
        const INV_EXP: U448 = U448::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffd");
        Self(self.0.pow(&INV_EXP))
    }

    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Squares a field element  `n` times
    fn square_n(&self, mut n: u32) -> FieldElement {
        let mut result = self.square();

        // Decrease value by 1 since we just did a squaring
        n -= 1;

        for _ in 0..n {
            result = result.square();
        }

        result
    }

    pub fn is_square(&self) -> Choice {
        const IS_SQUARE_EXP: U448 = U448::from_le_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        self.0.pow(&IS_SQUARE_EXP).ct_eq(&FieldElement::ONE.0)
    }

    pub fn sqrt(&self) -> FieldElement {
        const SQRT_EXP: U448 = U448::from_be_hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000000000000000000000000000000000000000");
        Self(self.0.pow(&SQRT_EXP))
    }

    pub fn to_bytes(self) -> [u8; 56] {
        let mut bytes = [0u8; 56];
        bytes.copy_from_slice(&self.0.retrieve().to_le_bytes()[..56]);
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 56]) -> Self {
        Self(ResidueType::new(&U448::from_le_slice(bytes)))
    }

    pub fn double(&self) -> Self {
        Self(self.0.add(&self.0))
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
        l1 = l2.square_n(3);
        l0 = l2 * l1;
        l1 = l0.square_n(3);
        l0 = l2 * l1;
        l2 = l0.square_n(9);
        l1 = l0 * l2;
        l0 = l1 * l1;
        l2 = l0 * self;
        l0 = l2.square_n(18);
        l2 = l1 * l0;
        l0 = l2.square_n(37);
        l1 = l2 * l0;
        l0 = l1.square_n(37);
        l1 = l2 * l0;
        l0 = l1.square_n(111);
        l2 = l1 * l0;
        l0 = l2.square();
        l1 = l0 * self;
        l0 = l1.square_n(223);
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

    /// Computes the square root ratio of two elements
    ///
    /// The difference between this and `sqrt_ratio` is that
    /// if the input is non-square, the function returns a result with
    /// a defined relationship to the inputs.
    pub(crate) fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (FieldElement, Choice) {
        const P_MINUS_THREE_DIV_4: U448 = U448::from_be_hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let u = u.0;
        let v = v.0;

        let r = u * (u * v).pow(&P_MINUS_THREE_DIV_4);
        let check = v * r.square();
        let was_square = check.ct_eq(&u);

        let mut r = FieldElement(r);
        r.conditional_negate(r.is_negative());
        (r, was_square)
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

    pub(crate) fn map_to_curve_decaf448(&self) -> TwistedExtendedPoint {
        const ONE_MINUS_TWO_D: FieldElement =
            FieldElement(ResidueType::new(&U448::from_u64(78163)));

        let r = -(self.square());
        let u0 = Self::EDWARDS_D * (r - Self::ONE);
        let u1 = (u0 + Self::ONE) * (u0 - r);

        let rhs = (r + Self::ONE) * u1;
        let (v, was_square) = Self::sqrt_ratio_i(&ONE_MINUS_TWO_D, &rhs);

        let mut v_prime = self * v;
        v_prime.conditional_assign(&v, was_square);
        let mut sgn = Self::MINUS_ONE;
        sgn.conditional_negate(was_square);

        let s = v_prime * (r + Self::ONE);
        let s2 = s.square();
        let s_abs = Self::conditional_select(&s, &s.neg(), s.is_negative());

        let w0 = s_abs + s_abs;
        let w1 = s2 + Self::ONE;
        let w2 = s2 - Self::ONE;
        let w3 = v_prime * s * (r - Self::ONE) * ONE_MINUS_TWO_D + sgn;

        EdwardsPoint {
            X: w0 * w3,
            Y: w2 * w1,
            Z: w1 * w3,
            T: w0 * w2,
        }
        .to_twisted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXof, Expander};
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
            let mut expander =
                ExpandMsgXof::<Shake256>::expand_message(&[msg], &[DST], 84 * 2).unwrap();
            let mut data = GenericArray::<u8, U84>::default();
            expander.fill_bytes(&mut data);
            let u0 = FieldElement::from_okm(&data);
            let mut e_u0 = *expected_u0;
            e_u0.reverse();
            let mut e_u1 = *expected_u1;
            e_u1.reverse();
            assert_eq!(u0.to_bytes(), e_u0);
            expander.fill_bytes(&mut data);
            let u1 = FieldElement::from_okm(&data);
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
            let mut expander =
                ExpandMsgXof::<Shake256>::expand_message(&[msg], &[DST], 84 * 2).unwrap();
            let mut data = GenericArray::<u8, U84>::default();
            expander.fill_bytes(&mut data);
            let u0 = FieldElement::from_okm(&data);
            let mut e_u0 = *expected_u0;
            e_u0.reverse();
            let mut e_u1 = *expected_u1;
            e_u1.reverse();
            assert_eq!(u0.to_bytes(), e_u0);
            expander.fill_bytes(&mut data);
            let u1 = FieldElement::from_okm(&data);
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
