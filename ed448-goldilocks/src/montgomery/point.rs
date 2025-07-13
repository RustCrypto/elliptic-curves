use crate::constants::MONTGOMERY_BASEPOINT_ORDER;
use crate::field::ConstMontyType;
use crate::field::FieldElement;
use crate::{AffinePoint, Curve448, Curve448FieldBytes, MontgomeryScalar};
use elliptic_curve::{
    CurveGroup, Error, Group,
    array::Array,
    bigint::U448,
    consts::U57,
    group::{GroupEncoding, cofactor::CofactorGroup, prime::PrimeGroup},
    ops::LinearCombination,
    point::{AffineCoordinates, NonIdentity},
    zeroize::DefaultIsZeroes,
};
use hash2curve::{ExpandMsgXof, GroupDigest};
use rand_core::TryRngCore;
use sha3::Shake256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{
    DEFAULT_ENCODE_TO_CURVE_SUITE, DEFAULT_HASH_TO_CURVE_SUITE, MontgomeryXpoint,
    ProjectiveMontgomeryXpoint,
};

/// A point in Montgomery form including the y-coordinate.
#[derive(Copy, Clone, Debug, Default)]
pub struct MontgomeryPoint {
    x: FieldElement,
    y: FieldElement,
}

impl MontgomeryPoint {
    pub(crate) fn new(x: FieldElement, y: FieldElement) -> Self {
        Self { x, y }
    }

    /// Convert this point to an [`AffinePoint`]
    // https://www.rfc-editor.org/rfc/rfc7748#section-4.2
    pub fn to_edwards(&self) -> AffinePoint {
        let u = self.x;
        let v = self.y;

        let u_sq = self.x.square();
        let u_sq_minus_1 = u_sq - FieldElement::ONE;
        let u_sq_minus_1_sq = u_sq_minus_1.square();
        let v_sq_2 = v.square().double();
        let v_sq_4 = v_sq_2.double();

        let xn = v.double().double() * u_sq_minus_1;
        let xd = u_sq_minus_1_sq + v_sq_4;

        let yn = -u * (u_sq_minus_1_sq - v_sq_4);
        let yd = u * u_sq_minus_1_sq - v_sq_2 * (u_sq + FieldElement::ONE);

        let d = (xd * yd).invert();

        let x = xn * yd * d;
        let y = yn * xd * d;

        AffinePoint { x, y }
    }

    /// Convert the point to its form without the y-coordinate
    pub fn to_affine_x(&self) -> MontgomeryXpoint {
        MontgomeryXpoint(self.x.to_bytes())
    }
}

impl ConditionallySelectable for MontgomeryPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl ConstantTimeEq for MontgomeryPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl DefaultIsZeroes for MontgomeryPoint {}

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for MontgomeryPoint {}

impl AffineCoordinates for MontgomeryPoint {
    type FieldRepr = Curve448FieldBytes;

    fn x(&self) -> Self::FieldRepr {
        self.x.to_bytes().into()
    }

    fn y(&self) -> Self::FieldRepr {
        self.y.to_bytes().into()
    }

    fn x_is_odd(&self) -> Choice {
        self.x.is_negative()
    }

    fn y_is_odd(&self) -> Choice {
        self.y.is_negative()
    }
}

impl From<ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        value.to_affine()
    }
}

impl From<NonIdentity<MontgomeryPoint>> for MontgomeryPoint {
    fn from(affine: NonIdentity<MontgomeryPoint>) -> Self {
        affine.to_point()
    }
}

/// The constant-time alternative is available at [`NonIdentity::new()`].
impl TryFrom<MontgomeryPoint> for NonIdentity<MontgomeryPoint> {
    type Error = Error;

    fn try_from(affine_point: MontgomeryPoint) -> Result<Self, Error> {
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

    fn double(&self) -> Self {
        self + self
    }

    /// Convert the point to its form without the y-coordinate
    pub fn to_projective_x(&self) -> ProjectiveMontgomeryXpoint {
        ProjectiveMontgomeryXpoint::new(self.U, self.W)
    }

    /// Convert the point to affine form without the y-coordinate
    pub fn to_affine_x(&self) -> MontgomeryXpoint {
        self.to_projective_x().to_affine()
    }

    /// Convert this point to an [`AffinePoint`]
    pub fn to_edwards(&self) -> AffinePoint {
        self.to_affine().to_edwards()
    }

    /// Hash a message to a point on the curve
    ///
    /// Hash using the default domain separation tag and hash function.
    /// For more control see [`GroupDigest::hash_from_bytes()`].
    pub fn hash_with_defaults(msg: &[u8]) -> Self {
        Curve448::hash_from_bytes::<ExpandMsgXof<Shake256>>(&[msg], &[DEFAULT_HASH_TO_CURVE_SUITE])
            .expect("should never fail with the given `ExpandMsg` and `dst`")
    }

    /// Encode a message to a point on the curve
    ///
    /// Encode using the default domain separation tag and hash function.
    /// For more control see [`GroupDigest::encode_from_bytes()`].
    pub fn encode_with_defaults(msg: &[u8]) -> Self {
        Curve448::encode_from_bytes::<ExpandMsgXof<Shake256>>(
            &[msg],
            &[DEFAULT_ENCODE_TO_CURVE_SUITE],
        )
        .expect("should never fail with the given `ExpandMsg` and `dst`")
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
        self.U.ct_eq(&other.U) & self.V.ct_eq(&other.V) & self.W.ct_eq(&other.W)
    }
}

impl Default for ProjectiveMontgomeryPoint {
    fn default() -> Self {
        Self::IDENTITY
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

impl PartialEq for ProjectiveMontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
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
        (self * MONTGOMERY_BASEPOINT_ORDER).ct_eq(&Self::IDENTITY)
    }
}

impl Group for ProjectiveMontgomeryPoint {
    type Scalar = MontgomeryScalar;

    fn try_from_rng<R>(rng: &mut R) -> Result<Self, R::Error>
    where
        R: TryRngCore + ?Sized,
    {
        let mut uniform_bytes = [0u8; 112];
        rng.try_fill_bytes(&mut uniform_bytes)?;
        Ok(Self::hash_with_defaults(&uniform_bytes))
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
        self.double()
    }
}

impl CurveGroup for ProjectiveMontgomeryPoint {
    type AffineRepr = MontgomeryPoint;

    fn to_affine(&self) -> Self::AffineRepr {
        let W_inv = self.W.invert();
        let x = self.U * W_inv;
        let y = self.V * W_inv;

        MontgomeryPoint { x, y }
    }
}

impl GroupEncoding for ProjectiveMontgomeryPoint {
    type Repr = Array<u8, U57>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        // Safe to unwrap here as the underlying data structure is an array
        let (tag, bytes) = bytes.split_first().expect("slice is non-empty");

        let mut x_bytes: [u8; 56] = [0; 56];
        x_bytes.copy_from_slice(bytes);

        let (sign, valid) = match *tag {
            0x02 => (Choice::from(0), Choice::from(1)),
            0x03 => (Choice::from(1), Choice::from(1)),
            _ => (Choice::from(0), Choice::from(0)),
        };

        FieldElement::from_repr(&x_bytes).and_then(|x| {
            CtOption::new(
                ProjectiveMontgomeryXpoint::new(x, FieldElement::ONE).to_extended(sign),
                valid,
            )
        })
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        let affine = self.to_affine();
        let mut compressed_bytes = Array::default();

        compressed_bytes[0] = if affine.y.is_negative().unwrap_u8() == 1 {
            0x03
        } else {
            0x02
        };

        compressed_bytes[1..].copy_from_slice(&affine.x.to_bytes()[..]);
        compressed_bytes
    }
}

impl PrimeGroup for ProjectiveMontgomeryPoint {}

impl From<MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: MontgomeryPoint) -> Self {
        ProjectiveMontgomeryPoint {
            U: value.x,
            V: value.y,
            W: FieldElement::ONE,
        }
    }
}

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
    use hex_literal::hex;

    #[test]
    fn test_montgomery_edwards() {
        let scalar = MontgomeryScalar::from(200u32);

        // Montgomery scalar mul
        let montgomery_res = (ProjectiveMontgomeryPoint::GENERATOR * scalar).to_affine();
        // Goldilocks scalar mul
        let goldilocks_point = EdwardsPoint::GENERATOR
            .scalar_mul(&scalar.to_scalar())
            .to_affine();

        assert_eq!(goldilocks_point.to_montgomery(), montgomery_res);
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
            let p = Curve448::hash_from_bytes::<ExpandMsgXof<Shake256>>(&[msg], &[DST])
                .unwrap()
                .to_affine();
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
            let p = Curve448::encode_from_bytes::<ExpandMsgXof<Shake256>>(&[msg], &[DST])
                .unwrap()
                .to_affine();
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
