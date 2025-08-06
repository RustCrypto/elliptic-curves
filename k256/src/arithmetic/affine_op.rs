use crate::arithmetic::mul::{G1, G2, MINUS_B1, MINUS_B2, MINUS_LAMBDA, Radix16Decomposition};
use crate::arithmetic::projective::ENDOMORPHISM_BETA;
use crate::arithmetic::scalar::{Scalar, WideScalar};
use crate::{AffinePoint, FieldElement};
use core::ops::{Add, Mul, Neg};
use elliptic_curve::scalar::IsHigh;
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
                //  x1 == x2 but y1 != y2 → vertical line → point at infinity
                return PowdrAffinePoint(AffinePoint::IDENTITY);
            }
        }

        let dx = other.0.x - self.0.x;
        let invert = dx.invert().unwrap();

        let dy = other.0.y - self.0.y;
        let lambda = dy * invert;

        let x3 = lambda.square() - self.0.x - other.0.x;
        let y3 = lambda * (self.0.x + x3.negate(5)) - self.0.y;

        PowdrAffinePoint(AffinePoint {
            x: x3.normalize_weak(),
            y: y3.normalize_weak(),
            infinity: 0,
        })
    }
}

impl Neg for PowdrAffinePoint {
    type Output = PowdrAffinePoint;

    fn neg(self) -> PowdrAffinePoint {
        PowdrAffinePoint::neg(&self)
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

    /// Double the point.
    pub fn double(self) -> PowdrAffinePoint {
        if self.0.y.normalizes_to_zero().into() {
            return PowdrAffinePoint(AffinePoint::IDENTITY);
        }

        let num = FieldElement::from(3u64) * self.0.x.square();
        let denom = FieldElement::from(2u64) * self.0.y;
        let lambda = num * denom.invert().unwrap();

        let x3 = lambda.square() - FieldElement::from(2u64) * self.0.x;
        let y3 = lambda * (self.0.x + x3.negate(3)) - self.0.y;

        PowdrAffinePoint(AffinePoint {
            x: x3.normalize_weak(),
            y: y3.normalize_weak(),
            infinity: 0,
        })
    }

    fn neg(&self) -> Self {
        PowdrAffinePoint(AffinePoint {
            x: self.0.x,
            y: self.0.y.negate(1).normalize(),
            infinity: self.0.infinity,
        })
    }

    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PowdrAffinePoint(AffinePoint {
            x: FieldElement::conditional_select(&a.0.x, &b.0.x, choice),
            y: FieldElement::conditional_select(&a.0.y, &b.0.y, choice),
            infinity: a.0.infinity,
        })
    }

    /// Calculates SECP256k1 endomorphism: `self * lambda`.
    pub fn endomorphism(&self) -> Self {
        Self(AffinePoint {
            x: self.0.x * ENDOMORPHISM_BETA,
            y: self.0.y,
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
}

#[inline(always)]
fn mul(x: &PowdrAffinePoint, k: &Scalar) -> PowdrAffinePoint {
    lincomb(&[(*x, *k)])
}

/// multi scalar multiplication using Pippenger's algorithm
pub fn lincomb<const N: usize>(
    points_and_scalars: &[(PowdrAffinePoint, Scalar); N],
) -> PowdrAffinePoint {
    let mut tables = [(LookupTable::default(), LookupTable::default()); N];
    let mut digits = [(
        Radix16Decomposition::<33>::default(),
        Radix16Decomposition::<33>::default(),
    ); N];

    lincomb_pippenger(points_and_scalars, &mut tables, &mut digits)
}

fn lincomb_pippenger(
    xks: &[(PowdrAffinePoint, Scalar)],
    tables: &mut [(LookupTable, LookupTable)],
    digits: &mut [(Radix16Decomposition<33>, Radix16Decomposition<33>)],
) -> PowdrAffinePoint {
    xks.iter().enumerate().for_each(|(i, (x, k))| {
        let (r1, r2) = decompose_scalar(k);
        let x_beta = x.endomorphism();
        let (r1_sign, r2_sign) = (r1.is_high(), r2.is_high());

        let (r1_c, r2_c) = (
            Scalar::conditional_select(&r1, &-r1, r1_sign),
            Scalar::conditional_select(&r2, &-r2, r2_sign),
        );

        tables[i] = (
            LookupTable::from(&PowdrAffinePoint::conditional_select(x, &-*x, r1_sign)),
            LookupTable::from(&PowdrAffinePoint::conditional_select(
                &x_beta, &-x_beta, r2_sign,
            )),
        );

        digits[i] = (
            Radix16Decomposition::<33>::new(&r1_c),
            Radix16Decomposition::<33>::new(&r2_c),
        )
    });

    let mut acc = PowdrAffinePoint(AffinePoint::IDENTITY);
    for component in 0..xks.len() {
        let (digit1, digit2) = digits[component];
        let (table1, table2) = tables[component];

        acc = table1.select(digit1.0[32]) + acc;
        acc = table2.select(digit2.0[32]) + acc;
    }

    for i in (0..32).rev() {
        for _j in 0..4 {
            acc = acc.double();
        }

        for component in 0..xks.len() {
            let (digit1, digit2) = digits[component];
            let (table1, table2) = tables[component];

            acc = table1.select(digit1.0[i]) + acc;
            acc = table2.select(digit2.0[i]) + acc;
        }
    }

    acc
}

/// Find r1 and r2 given k, such that r1 + r2 * lambda == k mod n.
fn decompose_scalar(k: &Scalar) -> (Scalar, Scalar) {
    // these _vartime calls are constant time since the shift amount is constant
    let c1 = WideScalar::mul_shift_vartime(k, &G1, 384) * MINUS_B1;
    let c2 = WideScalar::mul_shift_vartime(k, &G2, 384) * MINUS_B2;
    let r2 = c1 + c2;
    let r1 = k + r2 * MINUS_LAMBDA;

    (r1, r2)
}

#[derive(Copy, Clone, Default)]
struct LookupTable([PowdrAffinePoint; 8]);

impl From<&PowdrAffinePoint> for LookupTable {
    fn from(p: &PowdrAffinePoint) -> Self {
        let mut points = [*p; 8];
        for j in 0..7 {
            points[j + 1] = *p + points[j];
        }
        LookupTable(points)
    }
}

impl LookupTable {
    /// Given -8 <= x <= 8, returns x * p in constant time.
    fn select(&self, x: i8) -> PowdrAffinePoint {
        debug_assert!((-8..=8).contains(&x));

        if x == 0 {
            PowdrAffinePoint(AffinePoint::IDENTITY)
        } else {
            let abs = x.unsigned_abs() as usize;
            let mut point = self.0[abs - 1];

            if x < 0 {
                point.0.y = -point.0.y;
                point.0.y = point.0.y.normalize();
            }

            point
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::FieldBytes;
    use crate::arithmetic::{ProjectivePoint, Scalar};
    use elliptic_curve::PrimeField;
    use elliptic_curve::{
        Field, Group,
        rand_core::{OsRng, TryRngCore},
    };
    use hex_literal::hex;

    #[test]
    fn test_addition_double() {
        let x1: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[{
                let mut bytes = [0u8; 32];
                bytes[31] = 1;
                bytes
            }])[0],
        )
        .unwrap();
        let y1: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE"
            )])[0],
        )
        .unwrap()
        .normalize();

        let x2: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[{
                let mut bytes = [0u8; 32];
                bytes[31] = 2;
                bytes
            }])[0],
        )
        .unwrap();

        let y2: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "990418D84D45F61F60A56728F5A10317BDB3A05BDA4425E3AEE079F8A847A8D1"
            )])[0],
        )
        .unwrap()
        .normalize();

        let x3: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "F23A2D865C24C99CC9E7B99BD907FB93EBD6CCCE106BCCCB0082ACF8315E67BE"
            )])[0],
        )
        .unwrap()
        .normalize();

        let y3: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "791DFC78B49C9B5882867776F18BA7883ED0BAE1C0A856D26D41D38FB47345B4"
            )])[0],
        )
        .unwrap()
        .normalize();

        let x4: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "33333333333333333333333333333333333333333333333333333332FFFFFF3B"
            )])[0],
        )
        .unwrap()
        .normalize();

        let y4: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "3916485F2C3D80C62048C6FD8ACBF71EED11987A55CC10ABDC4E4A25C4EC54AC"
            )])[0],
        )
        .unwrap()
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
        let x1: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[{
                let mut bytes = [0u8; 32];
                bytes[31] = 1;
                bytes
            }])[0],
        )
        .unwrap();
        let y1: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE"
            )])[0],
        )
        .unwrap()
        .normalize();

        let x5: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "6D6D216817A448DC312FEE586FA306D189CB404A9CAF72D90308797F38934A19"
            )])[0],
        )
        .unwrap()
        .normalize();

        let y5: FieldElement = FieldElement::from_bytes(
            &FieldBytes::cast_slice_from_core(&[hex!(
                "2C9BB19372B2E1B830B5F4D92ADBAFEAAEB612026122E571D1BEA76D742F279E"
            )])[0],
        )
        .unwrap()
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
        let a_projective = ProjectivePoint::random(&mut OsRng.unwrap_mut());
        let b_projective = ProjectivePoint::random(&mut OsRng.unwrap_mut());

        let k = Scalar::random(&mut OsRng.unwrap_mut());
        let l = Scalar::random(&mut OsRng.unwrap_mut());

        let a_powdr_affine = PowdrAffinePoint(a_projective.to_affine());

        let b_powdr_affine = PowdrAffinePoint(b_projective.to_affine());

        let result_affine =
            lincomb(&[(a_powdr_affine, k), (b_powdr_affine, l)]).normalize_coordinates();
        let result_projective = a_projective * k + b_projective * l;

        assert_eq!(result_affine.0.x, result_projective.to_affine().x);
        assert_eq!(result_affine.0.y, result_projective.to_affine().y);
    }
}
