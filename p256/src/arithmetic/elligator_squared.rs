//! An implementation of the [Elligator Squared](https://eprint.iacr.org/2014/043.pdf) algorithm
//! for encoding elliptic curve points as uniformly distributed bitstrings.

use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::rand_core::RngCore;
use elliptic_curve::{Field, Group};

use crate::arithmetic::field::FieldElement;
use crate::arithmetic::{CURVE_EQUATION_A, CURVE_EQUATION_B};
use crate::{AffinePoint, ProjectivePoint};

/// Decodes the given pair of field elements into the originally encoded point.
pub fn elligator_squared_to_point(u: &FieldElement, v: &FieldElement) -> ProjectivePoint {
    f(u).to_curve() + f(v).to_curve()
}

/// Encodes the given point as a pair of random, uniformly distributed field elements.
pub fn point_to_elligator_squared(
    p: &ProjectivePoint,
    mut rng: impl RngCore,
) -> (FieldElement, FieldElement) {
    for _ in 0..1000 {
        // Generate a random field element \not\in {-1, 0, 1}.
        let u = FieldElement::random(&mut rng);
        if u == -FieldElement::ONE || u == FieldElement::ZERO || u == FieldElement::ONE {
            continue;
        }

        // Map the field element to a point and calculate the difference between the random point
        // and the input point.
        let q = p - &f(&u);

        // If we managed to randomly generate -p, congratulate ourselves on the improbable and keep
        // trying.
        if q.is_identity().into() {
            continue;
        }

        // Pick a random biquadratic root.
        let mut j = [0u8; 1];
        rng.fill_bytes(&mut j);
        let j = (j[0] % 4) as usize; // d = 4

        // If the Jth biquadratic root exists for the delta point, return our random field element
        // and our preimage field element.
        if let Some(v) = r(&q, j) {
            return (u, v);
        }
    }

    unreachable!()
}

fn g(x: &FieldElement) -> FieldElement {
    x.cube() + (CURVE_EQUATION_A * x) + CURVE_EQUATION_B
}

fn x_0(u: &FieldElement) -> FieldElement {
    -(CURVE_EQUATION_B * CURVE_EQUATION_A.invert().unwrap())
        * (FieldElement::ONE + ((u.square() * u.square()) - u.square()).invert().unwrap())
}

fn x_1(u: &FieldElement) -> FieldElement {
    -u.square() * x_0(u)
}

fn f(u: &FieldElement) -> AffinePoint {
    // Case 1: u \in {-1, 0, 1}
    // return: infinity
    if u == &-FieldElement::ONE || u == &FieldElement::ZERO || u == &FieldElement::ONE {
        return AffinePoint::IDENTITY;
    }

    // Case 2: u \not\in {-1, 0, 1} and g(X_0(u)) is a square
    // return: (X_0(u), \sqrt{g(X_0(u))})
    let x = x_0(u);
    let y = g(&x);
    if let Some(y) = y.sqrt().into() {
        return AffinePoint { x, y, infinity: 0 };
    }

    // Case 3: u \not\in {-1, 0, 1} and g(X_0(u)) is not a square
    // return: (X_1(u), -\sqrt{g(X_1(u))})
    let x = x_1(u);
    let y = -g(&x).sqrt().unwrap();
    AffinePoint { x, y, infinity: 0 }
}

fn r(q: &ProjectivePoint, j: usize) -> Option<FieldElement> {
    let q = q.to_affine();
    if q.y.sqrt().is_some().into() {
        if j == 0 {
            x0_r0(&q.x)
        } else if j == 1 {
            x0_r1(&q.x)
        } else if j == 2 {
            x0_r2(&q.x)
        } else {
            x0_r3(&q.x)
        }
    } else if j == 0 {
        x1_r0(&q.x)
    } else if j == 1 {
        x1_r1(&q.x)
    } else if j == 2 {
        x1_r2(&q.x)
    } else {
        x1_r3(&q.x)
    }
}

fn x0_r0(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = (TWO * omega).invert().into();
    let c: Option<FieldElement> = ((omega + a?) * b?).sqrt().into();
    c
}

fn x0_r1(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = (TWO * omega).invert().into();
    let c: Option<FieldElement> = ((omega + a?) * b?).sqrt().into();
    Some(-c?)
}

fn x0_r2(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = (TWO * omega).invert().into();
    let c: Option<FieldElement> = ((omega - a?) * b?).sqrt().into();
    c
}

fn x0_r3(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = (TWO * omega).invert().into();
    let c: Option<FieldElement> = ((omega - a?) * b?).sqrt().into();
    Some(-c?)
}

fn x1_r0(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = TWO.invert().into();
    let c: Option<FieldElement> = ((omega + a?) * b?).sqrt().into();
    c
}

fn x1_r1(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = TWO.invert().into();
    let c: Option<FieldElement> = ((omega + a?) * b?).sqrt().into();
    Some(-c?)
}

fn x1_r2(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = TWO.invert().into();
    let c: Option<FieldElement> = ((omega - a?) * b?).sqrt().into();
    c
}

fn x1_r3(x: &FieldElement) -> Option<FieldElement> {
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;
    let a: Option<FieldElement> = (omega.square() - (FOUR * omega)).sqrt().into();
    let b: Option<FieldElement> = TWO.invert().into();
    let c: Option<FieldElement> = ((omega - a?) * b?).sqrt().into();
    Some(-c?)
}

const TWO: FieldElement = FieldElement::add(&FieldElement::ONE, &FieldElement::ONE);
const FOUR: FieldElement = TWO.square();

#[cfg(test)]
mod tests {
    use elliptic_curve::group::GroupEncoding;
    use elliptic_curve::Group;

    use crate::ProjectivePoint;

    use super::*;

    #[test]
    fn swu_encoding() {
        let mut rng = rand_core::OsRng::default();
        for _ in 0..1_000 {
            let u = FieldElement::random(&mut rng);
            let q = f(&u);

            // Check to see if the point is actually on the curve.
            let b = q.to_bytes();
            let q_p: Option<AffinePoint> = AffinePoint::from_bytes(&b).into();
            assert_eq!(Some(q), q_p);
        }
    }

    #[test]
    fn round_trip() {
        let mut rng = rand_core::OsRng::default();
        for _ in 0..100 {
            let p = ProjectivePoint::random(&mut rng);
            let (u, v) = point_to_elligator_squared(&p, &mut rng);
            let p2 = elligator_squared_to_point(&u, &v);

            assert_eq!(p, p2);
        }
    }
}
