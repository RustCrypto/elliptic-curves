use elliptic_curve::{
    CurveGroup, Error, FieldBytes, Group,
    array::Array,
    bigint::U448,
    consts::U56,
    group::GroupEncoding,
    group::cofactor::CofactorGroup,
    group::prime::PrimeGroup,
    ops::LinearCombination,
    point::{AffineCoordinates, DecompressPoint, NonIdentity},
    zeroize::DefaultIsZeroes,
};
use rand_core::TryRngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{MontgomeryScalar, MontgomeryXpoint, ProjectiveMontgomeryXpoint};
use crate::field::{ConstMontyType, FieldElement};
use crate::{AffinePoint, Curve448, Curve448FieldBytes, ORDER};

/// A point in Montgomery form including the y-coordinate.
#[derive(Copy, Clone, Debug, Default, Eq)]
pub struct AffineMontgomeryPoint {
    pub(super) U: FieldElement,
    pub(super) V: FieldElement,
}

impl AffineMontgomeryPoint {
    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        U: FieldElement::ZERO,
        V: FieldElement::ONE,
    };

    pub(crate) fn new(U: FieldElement, V: FieldElement) -> Self {
        Self { U, V }
    }

    /// Generate a random [`AffineMontgomeryPoint`].
    pub fn try_from_rng<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryRngCore + ?Sized,
    {
        let mut bytes = Array::default();
        let mut sign = 0;

        loop {
            rng.try_fill_bytes(&mut bytes)?;
            rng.try_fill_bytes(core::array::from_mut(&mut sign))?;
            if let Some(point) = Self::decompress(&bytes, Choice::from(sign & 1)).into() {
                return Ok(point);
            }
        }
    }
}

impl ConditionallySelectable for AffineMontgomeryPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            V: FieldElement::conditional_select(&a.V, &b.V, choice),
        }
    }
}

impl ConstantTimeEq for AffineMontgomeryPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.U.ct_eq(&other.U) & self.V.ct_eq(&other.V)
    }
}

impl PartialEq for AffineMontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl From<&AffineMontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: &AffineMontgomeryPoint) -> Self {
        ProjectiveMontgomeryPoint {
            U: value.U,
            V: value.V,
            W: FieldElement::ONE,
        }
    }
}

impl From<AffineMontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: AffineMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&AffineMontgomeryPoint> for MontgomeryXpoint {
    fn from(value: &AffineMontgomeryPoint) -> Self {
        MontgomeryXpoint(value.U.to_bytes())
    }
}

impl From<AffineMontgomeryPoint> for MontgomeryXpoint {
    fn from(value: AffineMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&AffineMontgomeryPoint> for AffinePoint {
    // https://www.rfc-editor.org/rfc/rfc7748#section-4.2
    fn from(value: &AffineMontgomeryPoint) -> AffinePoint {
        let x = value.U;
        let y = value.V;
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

        let x = xNum * xDen.invert();
        let y = yNum * yDen.invert();

        AffinePoint::conditional_select(
            &AffinePoint { x, y },
            &AffinePoint::IDENTITY,
            value.ct_eq(&AffineMontgomeryPoint::IDENTITY),
        )
    }
}

impl From<AffineMontgomeryPoint> for AffinePoint {
    fn from(value: AffineMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl DefaultIsZeroes for AffineMontgomeryPoint {}

impl AffineCoordinates for AffineMontgomeryPoint {
    type FieldRepr = Curve448FieldBytes;

    fn from_coordinates(x: &Self::FieldRepr, y: &Self::FieldRepr) -> CtOption<Self> {
        let x = FieldElement::from_bytes(&x.0);
        let y = FieldElement::from_bytes(&y.0);

        // y^2 = x^3 + A*x^2 + x
        let left = y.square();
        let xx = x.square();
        let right = x.square() * x + FieldElement::J * xx + x;
        let is_on_curve = left.ct_eq(&right);

        CtOption::new(Self { U: x, V: y }, is_on_curve)
    }

    fn x(&self) -> Self::FieldRepr {
        self.U.to_bytes().into()
    }

    fn y(&self) -> Self::FieldRepr {
        self.V.to_bytes().into()
    }

    fn x_is_odd(&self) -> Choice {
        self.U.is_negative()
    }

    fn y_is_odd(&self) -> Choice {
        self.V.is_negative()
    }
}

impl DecompressPoint<Curve448> for AffineMontgomeryPoint {
    fn decompress(x: &FieldBytes<Curve448>, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_repr(&x.0).map(|_| MontgomeryXpoint(x.0).to_extended(y_is_odd))
    }
}

impl From<NonIdentity<AffineMontgomeryPoint>> for AffineMontgomeryPoint {
    fn from(affine: NonIdentity<AffineMontgomeryPoint>) -> Self {
        affine.to_point()
    }
}

/// The constant-time alternative is available at [`NonIdentity::new()`].
impl TryFrom<AffineMontgomeryPoint> for NonIdentity<AffineMontgomeryPoint> {
    type Error = Error;

    fn try_from(affine_point: AffineMontgomeryPoint) -> Result<Self, Error> {
        NonIdentity::new(affine_point).into_option().ok_or(Error)
    }
}

/// A Projective point in Montgomery form including the y-coordinate.
#[derive(Copy, Clone, Debug, Eq)]
pub struct ProjectiveMontgomeryPoint {
    pub(super) U: FieldElement,
    pub(super) V: FieldElement,
    pub(super) W: FieldElement,
}

impl ProjectiveMontgomeryPoint {
    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        U: FieldElement::ZERO,
        V: FieldElement::ONE,
        W: FieldElement::ZERO,
    };

    /// The generator point
    pub const GENERATOR: Self = Self {
        U: FieldElement(ConstMontyType::new(&U448::from_u64(5))),
        V: FieldElement(ConstMontyType::new(&U448::from_be_hex(
            "7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1a",
        ))),
        W: FieldElement::ONE,
    };

    pub(crate) fn new(U: FieldElement, V: FieldElement, W: FieldElement) -> Self {
        Self { U, V, W }
    }
}

impl ConditionallySelectable for ProjectiveMontgomeryPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            V: FieldElement::conditional_select(&a.V, &b.V, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

impl ConstantTimeEq for ProjectiveMontgomeryPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let UW = self.U * other.W;
        let WU = self.W * other.U;

        let VW = self.V * other.W;
        let WV = self.W * other.V;

        (UW.ct_eq(&WU)) & (VW.ct_eq(&WV))
    }
}

impl Default for ProjectiveMontgomeryPoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl PartialEq for ProjectiveMontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl From<&ProjectiveMontgomeryPoint> for AffineMontgomeryPoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        let W_inv = value.W.invert();
        let U = value.U * W_inv;
        let V = value.V * W_inv;

        AffineMontgomeryPoint { U, V }
    }
}

impl From<ProjectiveMontgomeryPoint> for AffineMontgomeryPoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&ProjectiveMontgomeryPoint> for ProjectiveMontgomeryXpoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        ProjectiveMontgomeryXpoint::conditional_select(
            &ProjectiveMontgomeryXpoint {
                U: value.U,
                W: value.W,
            },
            &ProjectiveMontgomeryXpoint::IDENTITY,
            value.ct_eq(&ProjectiveMontgomeryPoint::IDENTITY),
        )
    }
}

impl From<ProjectiveMontgomeryPoint> for ProjectiveMontgomeryXpoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&ProjectiveMontgomeryPoint> for MontgomeryXpoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        ProjectiveMontgomeryXpoint::from(value).to_affine()
    }
}

impl From<ProjectiveMontgomeryPoint> for MontgomeryXpoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl DefaultIsZeroes for ProjectiveMontgomeryPoint {}

impl<const N: usize> LinearCombination<[(ProjectiveMontgomeryPoint, MontgomeryScalar); N]>
    for ProjectiveMontgomeryPoint
{
}

impl LinearCombination<[(ProjectiveMontgomeryPoint, MontgomeryScalar)]>
    for ProjectiveMontgomeryPoint
{
}

impl CofactorGroup for ProjectiveMontgomeryPoint {
    type Subgroup = ProjectiveMontgomeryPoint;

    fn clear_cofactor(&self) -> Self::Subgroup {
        self.double().double()
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(self.clear_cofactor(), self.is_torsion_free())
    }

    fn is_torsion_free(&self) -> Choice {
        (self * MontgomeryScalar::new(*ORDER)).ct_eq(&Self::IDENTITY)
    }
}

impl Group for ProjectiveMontgomeryPoint {
    type Scalar = MontgomeryScalar;

    fn try_from_rng<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryRngCore + ?Sized,
    {
        loop {
            let point = AffineMontgomeryPoint::try_from_rng(rng)?;
            if point != AffineMontgomeryPoint::IDENTITY {
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

    // See Complete Addition Law for Montgomery Curves - Algorithm 3.
    // Slightly corrected from the derivation in the same paper.
    fn double(&self) -> Self {
        const A_MINUS_1: FieldElement = FieldElement(ConstMontyType::new(&U448::from_u64(156325)));

        let (x, y, z) = (self.U, self.V, self.W);

        let t0 = x.square();
        let t1 = y.square();
        let t2 = z.square();
        let t3 = (x + y).square();
        let t4 = (y + z).square();
        let t5 = (x + z).square();
        let t6 = t1 + t2;
        let t7 = (t0 - t2).double();
        let t8 = A_MINUS_1 * t0;
        let t9 = t0 - t1;
        let t10 = FieldElement::J * (t5 - t2) + t0 + t9;
        let t11 = t5 + t8;
        let t13 = t6.double(); // corrected - replaces t12

        let S_MINUS_U = t3 - t6;
        let S_PLUS_U = -S_MINUS_U + t7;
        let R_MINUS_T = t4 - t11;
        let R_PLUS_T = t4 - t13 + t11; // corrected
        let W_MINUS_S = t11 - t9;
        let W_PLUS_S = W_MINUS_S + t7;
        let T_MINUS_V = t11 - t10 - t13 + t8; // corrected
        let T_PLUS_V = t5 + t10;
        let U_MINUS_W = S_PLUS_U - W_PLUS_S;
        let R_PLUS_V = R_MINUS_T + T_PLUS_V;

        let C = R_PLUS_T * S_MINUS_U;
        let D = R_MINUS_T * S_PLUS_U;
        let E = T_PLUS_V * W_MINUS_S;
        let F = T_MINUS_V * W_PLUS_S;
        let X = C + D;
        let Y = E + F;
        let Z = U_MINUS_W.double() * R_PLUS_V + C - D + E - F;

        Self { U: X, V: Y, W: Z }
    }
}

impl CurveGroup for ProjectiveMontgomeryPoint {
    type AffineRepr = AffineMontgomeryPoint;

    fn to_affine(&self) -> Self::AffineRepr {
        let W_inv = self.W.invert();
        let U = self.U * W_inv;
        let V = self.V * W_inv;

        AffineMontgomeryPoint { U, V }
    }
}

impl GroupEncoding for ProjectiveMontgomeryPoint {
    type Repr = Array<u8, U56>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let mut bytes = bytes.0;
        let sign = bytes[0] & 1;
        bytes[0] &= 0xfe;

        FieldElement::from_repr(&bytes).map(|U| {
            ProjectiveMontgomeryXpoint {
                U,
                W: FieldElement::ONE,
            }
            .to_extended(Choice::from(sign))
        })
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        let affine = self.to_affine();
        let mut bytes = affine.U.to_bytes();

        if affine.V.is_negative().unwrap_u8() == 1 {
            bytes[0] |= 0x01;
        }

        bytes.into()
    }
}

impl PrimeGroup for ProjectiveMontgomeryPoint {}

impl From<NonIdentity<ProjectiveMontgomeryPoint>> for ProjectiveMontgomeryPoint {
    fn from(affine: NonIdentity<ProjectiveMontgomeryPoint>) -> Self {
        affine.to_point()
    }
}

/// The constant-time alternative is available at [`NonIdentity::new()`].
impl TryFrom<ProjectiveMontgomeryPoint> for NonIdentity<ProjectiveMontgomeryPoint> {
    type Error = Error;

    fn try_from(point: ProjectiveMontgomeryPoint) -> Result<Self, Error> {
        NonIdentity::new(point).into_option().ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EdwardsPoint;
    use crate::field::MODULUS;
    use elliptic_curve::bigint::modular::ConstMontyParams;
    use elliptic_curve::bigint::{ArrayEncoding, CheckedSub, Uint};
    use hash2curve::GroupDigest;
    use hex_literal::hex;

    #[test]
    fn decode() {
        let max_x = MODULUS::PARAMS.modulus().checked_sub(&Uint::ONE).unwrap();
        let y_positive = FieldElement(ConstMontyType::new(&Uint::from_le_hex(
            "6c4eae8a1ede852ca59c4154edf766c0a4bdddfae9cd34077529182d01af45c996aa714b714fe34341d5445fe41aed77d0ee49d6f7c5b245",
        )));
        let y_negative = -y_positive;

        let point = ProjectiveMontgomeryPoint::from_bytes(&max_x.to_le_byte_array()).unwrap();
        assert_eq!(point.U, FieldElement(ConstMontyType::new(&max_x)));
        assert_eq!(point.V, y_positive);
        assert_eq!(point.W, FieldElement::ONE);

        let mut bytes = max_x.to_le_byte_array();
        assert_eq!(bytes[0] & 1, 0x00);
        bytes[0] |= 0x01;
        let point = ProjectiveMontgomeryPoint::from_bytes(&bytes).unwrap();
        assert_eq!(point.U, FieldElement(ConstMontyType::new(&max_x)));
        assert_eq!(point.V, y_negative);
        assert_eq!(point.W, FieldElement::ONE);
    }

    #[test]
    fn encode() {
        let max_x = MODULUS::PARAMS.modulus().checked_sub(&Uint::ONE).unwrap();
        let y_positive = FieldElement(ConstMontyType::new(&Uint::from_le_hex(
            "6c4eae8a1ede852ca59c4154edf766c0a4bdddfae9cd34077529182d01af45c996aa714b714fe34341d5445fe41aed77d0ee49d6f7c5b245",
        )));
        let y_negative = -y_positive;

        let point = ProjectiveMontgomeryPoint {
            U: FieldElement(ConstMontyType::new(&max_x)),
            V: y_positive,
            W: FieldElement::ONE,
        };
        assert_eq!(point.to_bytes(), max_x.to_le_byte_array());

        let point = ProjectiveMontgomeryPoint {
            U: FieldElement(ConstMontyType::new(&max_x)),
            V: y_negative,
            W: FieldElement::ONE,
        };
        let mut bytes = max_x.to_le_byte_array();
        assert_eq!(bytes[0] & 1, 0x00);
        bytes[0] |= 0x01;
        assert_eq!(point.to_bytes(), bytes);
    }

    #[test]
    fn to_edwards() {
        let scalar = MontgomeryScalar::from(200u32);

        // Montgomery scalar mul
        let montgomery_res = ProjectiveMontgomeryPoint::GENERATOR * scalar * scalar;
        // Goldilocks scalar mul
        let goldilocks_point = EdwardsPoint::GENERATOR * scalar.to_scalar() * scalar.to_scalar();

        assert_eq!(goldilocks_point.to_montgomery(), montgomery_res.into());
    }

    #[test]
    fn identity_to_edwards() {
        let edwards = AffinePoint::IDENTITY;
        let montgomery = AffineMontgomeryPoint::IDENTITY;

        assert_eq!(AffinePoint::from(montgomery), edwards);
    }

    #[test]
    fn identity_from_montgomery() {
        let edwards = EdwardsPoint::IDENTITY;
        let montgomery = AffineMontgomeryPoint::IDENTITY;

        assert_eq!(edwards.to_montgomery(), montgomery);
    }

    #[test]
    fn to_projective_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY;
        let identity = ProjectiveMontgomeryPoint::IDENTITY;

        assert_eq!(ProjectiveMontgomeryXpoint::from(identity), x_identity);
    }

    #[test]
    fn to_affine_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY.to_affine();
        let identity = MontgomeryXpoint::from(ProjectiveMontgomeryPoint::IDENTITY);

        assert_eq!(identity, x_identity);
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
            let p = Curve448::hash_from_bytes(msg, DST).unwrap().to_affine();
            let mut xx = [0u8; 56];
            xx.copy_from_slice(&x[..]);
            xx.reverse();
            let mut yy = [0u8; 56];
            yy.copy_from_slice(&y[..]);
            yy.reverse();
            assert_eq!(p.x(), xx);
            assert_eq!(p.y(), yy);
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
            let p = Curve448::encode_from_bytes(msg, DST).unwrap().to_affine();
            let mut xx = [0u8; 56];
            xx.copy_from_slice(&x[..]);
            xx.reverse();
            let mut yy = [0u8; 56];
            yy.copy_from_slice(&y[..]);
            yy.reverse();
            assert_eq!(p.x(), xx);
            assert_eq!(p.y(), yy);
        }
    }
}
