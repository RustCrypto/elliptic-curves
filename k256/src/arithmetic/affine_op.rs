use crate::arithmetic::mul::{lincomb, Endomorphism, Identity, LookupTable, Radix16Decomposition};
use crate::arithmetic::projective::ENDOMORPHISM_BETA;
use crate::arithmetic::scalar::Scalar;
use crate::arithmetic::FieldElement;
use crate::AffinePoint;
use core::ops::{Add, AddAssign, Mul, Neg, Sub};
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::point::Double;
use elliptic_curve::subtle::{Choice, ConditionallySelectable};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
/// A wrapper around `AffinePoint` that provides additional ecc operations on affine points.
pub struct PowdrAffinePoint(pub AffinePoint);

impl Add<PowdrAffinePoint> for PowdrAffinePoint {
    type Output = PowdrAffinePoint;

    fn add(self, other: PowdrAffinePoint) -> PowdrAffinePoint {
        if self.0.infinity != 0 {
            return other;
        }
        if other.0.infinity != 0 {
            return self;
        }

        if other.0.x == self.0.x {
            if self.0.y == other.0.y {
                return self.double();
            } else {
                return PowdrAffinePoint(AffinePoint::IDENTITY);
            }
        }

        let dx = other.0.x - self.0.x;
        let dx_inv = dx.invert().unwrap();

        let dy = other.0.y - self.0.y;
        let lambda = dy * dx_inv;

        let x3 = lambda.square() - self.0.x - other.0.x;
        let y3 = lambda * (self.0.x + x3.negate(5)) - self.0.y;

        PowdrAffinePoint(AffinePoint {
            x: x3.normalize_weak(),
            y: y3.normalize_weak(),
            infinity: 0,
        })
    }
}

impl AddAssign<PowdrAffinePoint> for PowdrAffinePoint {
    fn add_assign(&mut self, other: PowdrAffinePoint) {
        *self = *self + other;
    }
}

impl Neg for PowdrAffinePoint {
    type Output = PowdrAffinePoint;

    fn neg(self) -> PowdrAffinePoint {
        PowdrAffinePoint(self.0.neg())
    }
}

impl Sub<PowdrAffinePoint> for PowdrAffinePoint {
    type Output = PowdrAffinePoint;

    fn sub(self, other: PowdrAffinePoint) -> PowdrAffinePoint {
        Add::add(self, other.neg())
    }
}

impl Mul<Scalar> for PowdrAffinePoint {
    type Output = PowdrAffinePoint;

    fn mul(self, other: Scalar) -> PowdrAffinePoint {
        mul(&self, &other)
    }
}

impl PowdrAffinePoint {
    /// Reduces the coordinates of the point to their canonical form.
    pub fn normalize_coordinates(&self) -> Self {
        PowdrAffinePoint(AffinePoint {
            x: self.0.x.normalize(),
            y: self.0.y.normalize(),
            infinity: self.0.infinity,
        })
    }

    /// Returns the x-coordinate of the point.
    pub fn x(&self) -> FieldElement {
        self.0.x
    }

    /// Returns the y-coordinate of the point.
    pub fn y(&self) -> FieldElement {
        self.0.y
    }

    /// Returns the infinity flag of the point.
    pub fn is_identity(&self) -> bool {
        self.0.infinity == 1
    }

    /// Returns the generator point of the curve.
    pub fn generator() -> Self {
        PowdrAffinePoint(AffinePoint::generator())
    }

    /// multi scalar multiplication using Straus-Shamir trick
    pub fn lincomb<const N: usize>(
        points_and_scalars: &[(PowdrAffinePoint, Scalar); N],
    ) -> PowdrAffinePoint {
        let mut tables = [(LookupTable::default(), LookupTable::default()); N];
        let mut digits = [(
            Radix16Decomposition::<33>::default(),
            Radix16Decomposition::<33>::default(),
        ); N];

        lincomb::<PowdrAffinePoint>(points_and_scalars, &mut tables, &mut digits)
    }
}

impl ConditionallySelectable for PowdrAffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PowdrAffinePoint(AffinePoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl Endomorphism for PowdrAffinePoint {
    /// Calculates SECP256k1 endomorphism: `self * lambda`.
    fn endomorphism(&self) -> Self {
        Self(AffinePoint {
            x: self.0.x * ENDOMORPHISM_BETA,
            y: self.0.y,
            infinity: self.0.infinity,
        })
    }
}

impl Identity for PowdrAffinePoint {
    fn identity() -> Self {
        PowdrAffinePoint(AffinePoint::IDENTITY)
    }
}

impl Double for PowdrAffinePoint {
    /// Double the point.
    fn double(&self) -> PowdrAffinePoint {
        if self.0.y.normalizes_to_zero().into() {
            return PowdrAffinePoint(AffinePoint::IDENTITY);
        }

        let num = self.0.x.square().mul_single(3);
        let denom = self.0.y.mul_single(2);
        let lambda = num * denom.invert().unwrap();

        let x3 = lambda.square() + self.0.x.mul_single(2).negate(2);
        let y3 = lambda * (self.0.x + x3.negate(4)) - self.0.y;

        PowdrAffinePoint(AffinePoint {
            x: x3.normalize_weak(),
            y: y3.normalize_weak(),
            infinity: 0,
        })
    }
}

#[inline(always)]
fn mul(x: &PowdrAffinePoint, k: &Scalar) -> PowdrAffinePoint {
    PowdrAffinePoint::lincomb(&[(*x, *k)])
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::arithmetic::{ProjectivePoint, Scalar};
    use crate::FieldBytes;
    use elliptic_curve::PrimeField;
    use elliptic_curve::{rand_core::OsRng, Field, Group};
    use hex_literal::hex;

    #[test]
    fn test_addition_double() {
        let x1: FieldElement = FieldElement::from_bytes_unchecked(
            &[{
                let mut bytes = [0u8; 32];
                bytes[31] = 1;
                bytes
            }][0],
        );
        let y1: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE"
            )][0],
        )
        .normalize();

        let x2: FieldElement = FieldElement::from_bytes_unchecked(
            &[{
                let mut bytes = [0u8; 32];
                bytes[31] = 2;
                bytes
            }][0],
        );

        let y2: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "990418D84D45F61F60A56728F5A10317BDB3A05BDA4425E3AEE079F8A847A8D1"
            )][0],
        )
        .normalize();

        let x3: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "F23A2D865C24C99CC9E7B99BD907FB93EBD6CCCE106BCCCB0082ACF8315E67BE"
            )][0],
        )
        .normalize();

        let y3: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "791DFC78B49C9B5882867776F18BA7883ED0BAE1C0A856D26D41D38FB47345B4"
            )][0],
        )
        .normalize();

        let x4: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "33333333333333333333333333333333333333333333333333333332FFFFFF3B"
            )][0],
        )
        .normalize();

        let y4: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "3916485F2C3D80C62048C6FD8ACBF71EED11987A55CC10ABDC4E4A25C4EC54AC"
            )][0],
        )
        .normalize();

        let point1 = PowdrAffinePoint(AffinePoint {
            x: x1,
            y: y1,
            infinity: 0,
        });
        let point2 = PowdrAffinePoint(AffinePoint {
            x: x2,
            y: y2,
            infinity: 0,
        });

        let addition = (point1 + point2).normalize_coordinates();
        let double = point2.double().normalize_coordinates();
        assert_eq!(addition.0.x, x3);
        assert_eq!(addition.0.y, y3);

        assert_eq!(double.0.x, x4.normalize());
        assert_eq!(double.0.y, y4.normalize());
    }

    #[test]
    fn test_multiplication() {
        let x1: FieldElement = FieldElement::from_bytes_unchecked(
            &[{
                let mut bytes = [0u8; 32];
                bytes[31] = 1;
                bytes
            }][0],
        );
        let y1: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE"
            )][0],
        )
        .normalize();

        let x5: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "6D6D216817A448DC312FEE586FA306D189CB404A9CAF72D90308797F38934A19"
            )][0],
        )
        .normalize();

        let y5: FieldElement = FieldElement::from_bytes_unchecked(
            &[hex!(
                "2C9BB19372B2E1B830B5F4D92ADBAFEAAEB612026122E571D1BEA76D742F279E"
            )][0],
        )
        .normalize();

        let scalar = Scalar::from_u128(12345678);

        let point1 = PowdrAffinePoint(AffinePoint {
            x: x1,
            y: y1,
            infinity: 0,
        });
        let point5 = PowdrAffinePoint(AffinePoint {
            x: x5,
            y: y5,
            infinity: 0,
        });

        let multiplication = (point1 * scalar).normalize_coordinates();
        assert_eq!(multiplication.0.x, point5.0.x);
        assert_eq!(multiplication.0.y, point5.0.y);
    }

    #[test]
    /// Tests the multi scalar multiplication function using functions from projective points.
    fn test_lincomb() {
        let a_projective = ProjectivePoint::random(&mut OsRng);
        let b_projective = ProjectivePoint::random(&mut OsRng);

        let k = Scalar::random(&mut OsRng);
        let l = Scalar::random(&mut OsRng);

        let a_powdr_affine = PowdrAffinePoint(a_projective.to_affine());

        let b_powdr_affine = PowdrAffinePoint(b_projective.to_affine());

        let result_affine = PowdrAffinePoint::lincomb(&[(a_powdr_affine, k), (b_powdr_affine, l)])
            .normalize_coordinates();
        let result_projective = a_projective * k + b_projective * l;

        assert_eq!(result_affine.0.x, result_projective.to_affine().x);
        assert_eq!(result_affine.0.y, result_projective.to_affine().y);
    }
}
