use crate::field::ConstMontyType;
use crate::field::FieldElement;
use crate::field::FieldElementU84;
use crate::{AffinePoint, MontgomeryScalar};
use core::fmt::{self, Debug, Formatter};
use core::ops::Mul;
use elliptic_curve::array::Array;
use elliptic_curve::bigint::U448;
use elliptic_curve::consts::U28;
use elliptic_curve::consts::U84;
use elliptic_curve::zeroize::DefaultIsZeroes;
use hash2curve::Expander;
use hash2curve::FromOkm;
use hash2curve::{ExpandMsg, ExpandMsgXof};
use sha3::Shake256;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

use super::{
    DEFAULT_ENCODE_TO_CURVE_SUITE, DEFAULT_HASH_TO_CURVE_SUITE, MontgomeryPoint,
    ProjectiveMontgomeryPoint,
};

// Low order points on Curve448 and it's twist
const LOW_A: MontgomeryXpoint = MontgomeryXpoint([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const LOW_B: MontgomeryXpoint = MontgomeryXpoint([
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const LOW_C: MontgomeryXpoint = MontgomeryXpoint([
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

/// A point in Montgomery form
#[derive(Copy, Clone, Eq)]
pub struct MontgomeryXpoint(pub [u8; 56]);

impl Default for MontgomeryXpoint {
    fn default() -> MontgomeryXpoint {
        Self([0u8; 56])
    }
}

impl DefaultIsZeroes for MontgomeryXpoint {}

impl Debug for MontgomeryXpoint {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.0[..].fmt(formatter)
    }
}

impl ConstantTimeEq for MontgomeryXpoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for MontgomeryXpoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// A Projective point in Montgomery form
#[derive(Copy, Clone, Debug, Eq)]
pub struct ProjectiveMontgomeryXpoint {
    U: FieldElement,
    W: FieldElement,
}

impl Mul<&MontgomeryScalar> for &MontgomeryXpoint {
    type Output = MontgomeryXpoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, scalar: &MontgomeryScalar) -> MontgomeryXpoint {
        (&self.to_projective() * scalar).to_affine()
    }
}

impl Mul<&MontgomeryXpoint> for &MontgomeryScalar {
    type Output = MontgomeryXpoint;

    fn mul(self, point: &MontgomeryXpoint) -> MontgomeryXpoint {
        point * self
    }
}

impl MontgomeryXpoint {
    /// Returns the generator specified in RFC7748
    pub const GENERATOR: Self = Self([
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    /// Returns true if the point is one of the low order points
    pub fn is_low_order(&self) -> bool {
        (*self == LOW_A) || (*self == LOW_B) || (*self == LOW_C)
    }

    /// View the point as a byte slice
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }

    /// Compute the Y-coordinate
    pub fn y(&self, sign: Choice) -> [u8; 56] {
        self.to_projective().y(sign).to_bytes()
    }

    /// Convert the point to its form including the y-coordinate
    pub fn to_projective(&self) -> ProjectiveMontgomeryXpoint {
        ProjectiveMontgomeryXpoint {
            U: FieldElement::from_bytes(&self.0),
            W: FieldElement::ONE,
        }
    }

    /// Convert the point to projective form including the y-coordinate
    pub fn to_extended_projective(&self, sign: Choice) -> ProjectiveMontgomeryPoint {
        self.to_projective().to_extended(sign)
    }

    /// Convert the point to its form including the y-coordinate
    pub fn to_extended(&self, sign: Choice) -> MontgomeryPoint {
        self.to_projective().to_extended_affine(sign)
    }

    /// Convert this point to an [`AffinePoint`]
    pub fn to_edwards(&self, sign: Choice) -> AffinePoint {
        self.to_extended(sign).to_edwards()
    }
}

impl ConstantTimeEq for ProjectiveMontgomeryXpoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.U.ct_eq(&other.U) & self.W.ct_eq(&other.W)
    }
}

impl ConditionallySelectable for ProjectiveMontgomeryXpoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

impl PartialEq for ProjectiveMontgomeryXpoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Mul<&MontgomeryScalar> for &ProjectiveMontgomeryXpoint {
    type Output = ProjectiveMontgomeryXpoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, scalar: &MontgomeryScalar) -> ProjectiveMontgomeryXpoint {
        // Algorithm 8 of Costello-Smith 2017
        let mut x0 = ProjectiveMontgomeryXpoint::IDENTITY;
        let mut x1 = *self;

        let bits = scalar.bits();
        let mut swap = 0;
        for s in (0..448).rev() {
            let bit = bits[s] as u8;
            let choice: u8 = swap ^ bit;

            ProjectiveMontgomeryXpoint::conditional_swap(&mut x0, &mut x1, Choice::from(choice));
            differential_add_and_double(&mut x0, &mut x1, &self.U);

            swap = bit;
        }

        x0
    }
}

impl Mul<&ProjectiveMontgomeryXpoint> for &MontgomeryScalar {
    type Output = ProjectiveMontgomeryXpoint;

    fn mul(self, point: &ProjectiveMontgomeryXpoint) -> ProjectiveMontgomeryXpoint {
        point * self
    }
}

fn differential_add_and_double(
    P: &mut ProjectiveMontgomeryXpoint,
    Q: &mut ProjectiveMontgomeryXpoint,
    affine_PmQ: &FieldElement,
) {
    let t0 = P.U + P.W;
    let t1 = P.U - P.W;
    let t2 = Q.U + Q.W;
    let t3 = Q.U - Q.W;

    let t4 = t0.square(); // (U_P + W_P)^2 = U_P^2 + 2 U_P W_P + W_P^2
    let t5 = t1.square(); // (U_P - W_P)^2 = U_P^2 - 2 U_P W_P + W_P^2

    let t6 = t4 - t5; // 4 U_P W_P

    let t7 = t0 * t3; // (U_P + W_P) (U_Q - W_Q) = U_P U_Q + W_P U_Q - U_P W_Q - W_P W_Q
    let t8 = t1 * t2; // (U_P - W_P) (U_Q + W_Q) = U_P U_Q - W_P U_Q + U_P W_Q - W_P W_Q

    let t9 = t7 + t8; // 2 (U_P U_Q - W_P W_Q)
    let t10 = t7 - t8; // 2 (W_P U_Q - U_P W_Q)

    let t11 = t9.square(); // 4 (U_P U_Q - W_P W_Q)^2
    let t12 = t10.square(); // 4 (W_P U_Q - U_P W_Q)^2
    let t13 = FieldElement::A_PLUS_TWO_OVER_FOUR * t6; // (A + 2) U_P U_Q

    let t14 = t4 * t5; // ((U_P + W_P)(U_P - W_P))^2 = (U_P^2 - W_P^2)^2
    let t15 = t13 + t5; // (U_P - W_P)^2 + (A + 2) U_P W_P

    let t16 = t6 * t15; // 4 (U_P W_P) ((U_P - W_P)^2 + (A + 2) U_P W_P)
    let t17 = *affine_PmQ * t12; // U_D * 4 (W_P U_Q - U_P W_Q)^2
    let t18 = t11; // W_D * 4 (U_P U_Q - W_P W_Q)^2

    P.U = t14; // U_{P'} = (U_P + W_P)^2 (U_P - W_P)^2
    P.W = t16; // W_{P'} = (4 U_P W_P) ((U_P - W_P)^2 + ((A + 2)/4) 4 U_P W_P)
    Q.U = t18; // U_{Q'} = W_D * 4 (U_P U_Q - W_P W_Q)^2
    Q.W = t17; // W_{Q'} = U_D * 4 (W_P U_Q - U_P W_Q)^2
}

impl ProjectiveMontgomeryXpoint {
    pub(crate) fn new(U: FieldElement, W: FieldElement) -> Self {
        Self { U, W }
    }

    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        U: FieldElement::ONE,
        W: FieldElement::ZERO,
    };

    /// The generator point
    pub const GENERATOR: Self = Self {
        U: FieldElement(ConstMontyType::new(&U448::from_u64(5))),
        W: FieldElement::ONE,
    };

    // See https://www.rfc-editor.org/rfc/rfc7748#section-1
    fn y(&self, sign: Choice) -> FieldElement {
        // v^2 = u^3 + A*u^2 + u
        let u_sq = self.U.square();
        let v_sq = u_sq * self.U + FieldElement::J * u_sq + self.U;

        let mut v = v_sq.sqrt();
        v.conditional_negate(v.is_negative() ^ sign);
        v
    }

    /// Double this point
    // https://eprint.iacr.org/2020/1338.pdf (2.2)
    pub fn double(&self) -> Self {
        const C: FieldElement = FieldElement(ConstMontyType::new(&U448::from_u64(39082)));

        let v1 = (self.U + self.W).square();
        let v2 = (self.U - self.W).square();
        let U = v1 * v2;
        let v3 = v1 - v2;
        let v4 = C * v3;
        let v5 = v2 + v4;
        let W = v3 * v5;

        Self { U, W }
    }

    /// Hash a message to a point on the curve
    ///
    /// Hash using the default domain separation tag and hash function.
    /// For more control see [`Self::hash()`].
    pub fn hash_with_defaults(msg: &[u8]) -> Self {
        Self::hash::<ExpandMsgXof<Shake256>>(&[msg], &[DEFAULT_HASH_TO_CURVE_SUITE])
    }

    /// Hash a message to a point on the curve
    ///
    /// Implements hash to curve according
    /// see <https://datatracker.ietf.org/doc/rfc9380/>
    pub fn hash<X>(msg: &[&[u8]], dst: &[&[u8]]) -> Self
    where
        X: ExpandMsg<U28>,
    {
        let mut expander =
            X::expand_message(msg, dst, (84 * 2).try_into().expect("should never fail"))
                .expect("should never fail with the given `ExpandMsg` and `dst`");
        let mut data = Array::<u8, U84>::default();
        expander.fill_bytes(&mut data);
        let u0 = FieldElementU84::from_okm(&data).0;
        expander.fill_bytes(&mut data);
        let u1 = FieldElementU84::from_okm(&data).0;

        let (qx, qy) = u0.map_to_curve_elligator2();
        let q0 = ProjectiveMontgomeryPoint::new(qx, qy, FieldElement::ONE);
        let (qx, qy) = u1.map_to_curve_elligator2();
        let q1 = ProjectiveMontgomeryPoint::new(qx, qy, FieldElement::ONE);

        (q0 + q1).to_projective_x().double().double()
    }

    /// Encode a message to a point on the curve
    ///
    /// Encode using the default domain separation tag and hash function.
    /// For more control see [`Self::encode()`].
    pub fn encode_with_defaults(msg: &[u8]) -> Self {
        Self::encode::<ExpandMsgXof<Shake256>>(&[msg], &[DEFAULT_ENCODE_TO_CURVE_SUITE])
    }

    /// Encode a message to a point on the curve
    ///
    /// Implements encode to curve according
    /// see <https://datatracker.ietf.org/doc/rfc9380/>
    pub fn encode<X>(msg: &[&[u8]], dst: &[&[u8]]) -> Self
    where
        X: ExpandMsg<U28>,
    {
        let mut expander = X::expand_message(msg, dst, 84.try_into().expect("should never fail"))
            .expect("should never fail with the given `ExpandMsg` and `dst`");
        let mut data = Array::<u8, U84>::default();
        expander.fill_bytes(&mut data);
        let u = FieldElementU84::from_okm(&data).0;

        u.map_to_curve_elligator2_x().double().double()
    }

    /// Convert the point to affine form
    pub fn to_affine(&self) -> MontgomeryXpoint {
        let x = self.U * self.W.invert();
        MontgomeryXpoint(x.to_bytes())
    }

    /// Convert the point to affine form including the y-coordinate
    pub fn to_extended_affine(&self, sign: Choice) -> MontgomeryPoint {
        let x = self.U * self.W.invert();
        let y = self.y(sign);

        MontgomeryPoint::new(x, y)
    }

    /// Convert the point to its form including the y-coordinate
    pub fn to_extended(&self, sign: Choice) -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint::conditional_select(
            &ProjectiveMontgomeryPoint::new(self.U, self.y(sign), self.W),
            &ProjectiveMontgomeryPoint::IDENTITY,
            self.ct_eq(&Self::IDENTITY),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EdwardsPoint;
    use elliptic_curve::CurveGroup;
    use hex_literal::hex;
    use sha3::Shake256;

    #[test]
    fn to_edwards() {
        let scalar = MontgomeryScalar::from(200u32);

        // Montgomery scalar mul
        let montgomery_res = (&ProjectiveMontgomeryXpoint::GENERATOR * &scalar).to_affine();
        // Goldilocks scalar mul
        let goldilocks_point = EdwardsPoint::GENERATOR
            .scalar_mul(&scalar.to_scalar())
            .to_affine();

        assert_eq!(goldilocks_point.to_montgomery_x(), montgomery_res);
    }

    #[test]
    fn to_montgomery_extended_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY;
        let identity = ProjectiveMontgomeryPoint::IDENTITY;

        assert_eq!(x_identity.to_extended(Choice::from(1)), identity);
    }

    #[test]
    fn to_montgomery_extended_affine() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY.to_affine();
        let identity = ProjectiveMontgomeryPoint::IDENTITY.to_affine();

        assert_eq!(x_identity.to_extended(Choice::from(1)), identity);
    }

    #[test]
    fn hash_with_test_vectors() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_RO_";
        const MSGS: &[(&[u8], [u8; 56], [u8; 56])] = &[
            (b"", hex!("5ea5ff623d27c75e73717514134e73e419f831a875ca9e82915fdfc7069d0a9f8b532cfb32b1d8dd04ddeedbe3fa1d0d681c01e825d6a9ea"), hex!("afadd8de789f8f8e3516efbbe313a7eba364c939ecba00dabf4ced5c563b18e70a284c17d8f46b564c4e6ce11784a3825d941116622128c1")),
            (b"abc", hex!("9b2f7ce34878d7cebf34c582db14958308ea09366d1ec71f646411d3de0ae564d082b06f40cd30dfc08d9fb7cb21df390cf207806ad9d0e4"), hex!("138a0eef0a4993ea696152ed7db61f7ddb4e8100573591e7466d61c0c568ecaec939e36a84d276f34c402526d8989a96e99760c4869ed633")),
            (b"abcdef0123456789", hex!("f54ecd14b85a50eeeee0618452df3a75be7bfba11da5118774ae4ea55ac204e153f77285d780c4acee6c96abe3577a0c0b00be6e790cf194"), hex!("935247a64bf78c107069943c7e3ecc52acb27ce4a3230407c8357341685ea2152e8c3da93f8cd77da1bddb5bb759c6e7ae7d516dced42850")),
            (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hex!("5bd67c4f88adf6beb10f7e0d0054659776a55c97b809ec8b3101729e104fd0f684e103792f267fd87cc4afc25a073956ef4f268fb02824d5"), hex!("da1f5cb16a352719e4cb064cf47ba72aeba7752d03e8ca2c56229f419b4ef378785a5af1a53dd7ab4d467c1f92f7b139b3752faf29c96432")),
            (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex!("ea441c10b3636ecedd5c0dfcae96384cc40de8390a0ab648765b4508da12c586d55dc981275776507ebca0e4d1bcaa302bb69dcfa31b3451"), hex!("fee0192d49bcc0c28d954763c2cbe739b9265c4bebe3883803c64971220cfda60b9ac99ad986cd908c0534b260b5cfca46f6c2b0f3f21bda")),
        ];

        for (msg, x, y) in MSGS {
            let p = ProjectiveMontgomeryXpoint::hash::<ExpandMsgXof<Shake256>>(&[msg], &[DST])
                .to_affine();
            let mut xx = [0u8; 56];
            xx.copy_from_slice(&x[..]);
            xx.reverse();
            let mut yy = [0u8; 56];
            yy.copy_from_slice(&y[..]);
            yy.reverse();
            assert_eq!(p.0, xx);
            assert!(p.y(Choice::from(0)) == yy || p.y(Choice::from(1)) == yy);
        }
    }

    #[test]
    fn encode_with_test_vectors() {
        const DST: &[u8] = b"QUUX-V01-CS02-with-curve448_XOF:SHAKE256_ELL2_NU_";
        const MSGS: &[(&[u8], [u8; 56], [u8; 56])] = &[
            (b"", hex!("b65e8dbb279fd656f926f68d463b13ca7a982b32f5da9c7cc58afcf6199e4729863fb75ca9ae3c95c6887d95a5102637a1c5c40ff0aafadc"), hex!("ea1ea211cf29eca11c057fe8248181591a19f6ac51d45843a65d4bb8b71bc83a64c771ed7686218a278ef1c5d620f3d26b53162188645453")),
            (b"abc", hex!("51aceca4fa95854bbaba58d8a5e17a86c07acadef32e1188cafda26232131800002cc2f27c7aec454e5e0c615bddffb7df6a5f7f0f14793f"), hex!("c590c9246eb28b08dee816d608ef233ea5d76e305dc458774a1e1bd880387e6734219e2018e4aa50a49486dce0ba8740065da37e6cf5212c")),
            (b"abcdef0123456789", hex!("c6d65987f146b8d0cb5d2c44e1872ac3af1f458f6a8bd8c232ffe8b9d09496229a5a27f350eb7d97305bcc4e0f38328718352e8e3129ed71"), hex!("4d2f901bf333fdc4135b954f20d59207e9f6a4ecf88ce5af11c892b44f79766ec4ecc9f60d669b95ca8940f39b1b7044140ac2040c1bf659")),
            (b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", hex!("9b8d008863beb4a02fb9e4efefd2eba867307fb1c7ce01746115d32e1db551bb254e8e3e4532d5c74a83949a69a60519ecc9178083cbe943"), hex!("346a1fca454d1e67c628437c270ec0f0c4256bb774fe6c0e49de7004ff6d9199e2cd99d8f7575a96aafc4dc8db1811ba0a44317581f41371")),
            (b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hex!("8746dc34799112d1f20acda9d7f722c9abb29b1fb6b7e9e566983843c20bd7c9bfad21b45c5166b808d2f5d44e188f1fdaf29cdee8a72e4c"), hex!("7c1293484c9287c298a1a0600c64347eee8530acf563cd8705e05728274d8cd8101835f8003b6f3b78b5beb28f5be188a3d7bce1ec5a36b1")),
        ];

        for (msg, x, y) in MSGS {
            let p = ProjectiveMontgomeryXpoint::encode::<ExpandMsgXof<Shake256>>(&[msg], &[DST])
                .to_affine();
            let mut xx = [0u8; 56];
            xx.copy_from_slice(&x[..]);
            xx.reverse();
            let mut yy = [0u8; 56];
            yy.copy_from_slice(&y[..]);
            yy.reverse();
            assert_eq!(p.0, xx);
            assert!(p.y(Choice::from(0)) == yy || p.y(Choice::from(1)) == yy);
        }
    }
}
