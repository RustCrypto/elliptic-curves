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
pub struct MontgomeryPoint {
    pub(super) x: FieldElement,
    pub(super) y: FieldElement,
}

impl MontgomeryPoint {
    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
    };

    pub(crate) fn new(x: FieldElement, y: FieldElement) -> Self {
        Self { x, y }
    }

    /// Generate a random [`MontgomeryPoint`].
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

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl From<&MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: &MontgomeryPoint) -> Self {
        ProjectiveMontgomeryPoint {
            U: value.x,
            V: value.y,
            W: FieldElement::ONE,
        }
    }
}

impl From<MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: MontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&MontgomeryPoint> for MontgomeryXpoint {
    fn from(value: &MontgomeryPoint) -> Self {
        MontgomeryXpoint(value.x.to_bytes())
    }
}

impl From<MontgomeryPoint> for MontgomeryXpoint {
    fn from(value: MontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&MontgomeryPoint> for AffinePoint {
    // https://www.rfc-editor.org/rfc/rfc7748#section-4.2
    fn from(value: &MontgomeryPoint) -> AffinePoint {
        let x = value.x;
        let y = value.y;
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
            value.ct_eq(&MontgomeryPoint::IDENTITY),
        )
    }
}

impl From<MontgomeryPoint> for AffinePoint {
    fn from(value: MontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl DefaultIsZeroes for MontgomeryPoint {}

impl AffineCoordinates for MontgomeryPoint {
    type FieldRepr = Curve448FieldBytes;

    fn from_coordinates(x: &Self::FieldRepr, y: &Self::FieldRepr) -> CtOption<Self> {
        let x = FieldElement::from_bytes(&x.0);
        let y = FieldElement::from_bytes(&y.0);

        // y^2 = x^3 + A*x^2 + x
        let left = y.square();
        let xx = x.square();
        let right = x.square() * x + FieldElement::J * xx + x;
        let is_on_curve = left.ct_eq(&right);

        CtOption::new(Self { x, y }, is_on_curve)
    }

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

impl DecompressPoint<Curve448> for MontgomeryPoint {
    fn decompress(x: &FieldBytes<Curve448>, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_repr(&x.0).map(|_| MontgomeryXpoint(x.0).to_extended(y_is_odd))
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

impl From<&ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        let W_inv = value.W.invert();
        let x = value.U * W_inv;
        let y = value.V * W_inv;

        MontgomeryPoint { x, y }
    }
}

impl From<ProjectiveMontgomeryPoint> for MontgomeryPoint {
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
            let point = MontgomeryPoint::try_from_rng(rng)?;
            if point != MontgomeryPoint::IDENTITY {
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
    type AffineRepr = MontgomeryPoint;

    fn to_affine(&self) -> Self::AffineRepr {
        let W_inv = self.W.invert();
        let x = self.U * W_inv;
        let y = self.V * W_inv;

        MontgomeryPoint { x, y }
    }
}

impl GroupEncoding for ProjectiveMontgomeryPoint {
    type Repr = Array<u8, U56>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let mut bytes = bytes.0;
        let sign = bytes[0] & 1;
        bytes[0] &= 0xfe;

        FieldElement::from_repr(&bytes).map(|x| {
            ProjectiveMontgomeryXpoint {
                U: x,
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
        let mut bytes = affine.x.to_bytes();

        if affine.y.is_negative().unwrap_u8() == 1 {
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
        let montgomery = MontgomeryPoint::IDENTITY;

        assert_eq!(AffinePoint::from(montgomery), edwards);
    }

    #[test]
    fn identity_from_montgomery() {
        let edwards = EdwardsPoint::IDENTITY;
        let montgomery = MontgomeryPoint::IDENTITY;

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
}
