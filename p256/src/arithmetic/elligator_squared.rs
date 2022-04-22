//! An implementation of the [Elligator Squared](https://eprint.iacr.org/2014/043.pdf) algorithm
//! for encoding elliptic curve points as uniformly distributed bitstrings.

use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::rand_core::RngCore;
use elliptic_curve::subtle::CtOption;
use elliptic_curve::{Field, Group};

use crate::arithmetic::field::FieldElement;
use crate::arithmetic::{CURVE_EQUATION_A, CURVE_EQUATION_B};
use crate::{AffinePoint, FieldBytes, ProjectivePoint};

/// Decodes the given pair of field elements into the originally encoded point.
pub fn elligator_squared_to_point(u: &FieldBytes, v: &FieldBytes) -> Option<ProjectivePoint> {
    FieldElement::from_bytes(u)
        .and_then(|u| FieldElement::from_bytes(v).map(|v| f(&u).to_curve() + f(&v).to_curve()))
        .into()
}

/// Encodes the given point as a pair of random, uniformly distributed field elements.
pub fn point_to_elligator_squared(
    p: &ProjectivePoint,
    mut rng: impl RngCore,
) -> (FieldBytes, FieldBytes) {
    // Iterate through no more than one thousand candidates. On average, we try N(P) candidates.
    for _ in 0..1_000 {
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

        // Pick a random biquadratic root from [0,4).
        let j = rng.next_u32() as usize % 4;

        // If the Jth biquadratic root exists for the delta point, return our random field element
        // and our preimage field element.
        let v: Option<FieldElement> = r(&q, j).into();
        if let Some(v) = v {
            return (u.to_bytes(), v.to_bytes());
        }
    }

    // Statistically, it's more likely the RNG is broken than we found one thousand candidates in a
    // row with no valid preimage.
    unreachable!("failed to find candidate, suspect RNG failure")
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

fn r(q: &ProjectivePoint, j: usize) -> CtOption<FieldElement> {
    let q = q.to_affine();
    let (x, y) = (q.x, q.y);

    // Inverting `f` requires two branches, one for X_0 and one for X_1, each of which has four
    // roots. omega is constant across all of them.
    let omega = ((CURVE_EQUATION_A * CURVE_EQUATION_B.invert().unwrap()) * x) + FieldElement::ONE;

    (omega.square() - (FOUR * omega)).sqrt().and_then(|a| {
        // The first division in roots comes at \sqrt{\omega^2 - 4 \omega}. The first and second
        // roots have positive values, the third and fourth roots have negative values.
        let a = if j == 0 || j == 1 { a } else { -a };

        // If g(x) is square, then, x=X_0(u); otherwise x=X_1(u).
        (if y.sqrt().is_some().into() {
            // If x=X_0(u), then we divide by 2 \omega.
            (TWO * omega).invert()
        } else {
            // If x=X_1(u), then we divide by 2.
            TWO.invert()
        })
        .and_then(|b| {
            ((omega + a) * b)
                .sqrt()
                // The second division in roots comes here. The first and third roots have positive
                // values, the second and fourth roots have negative values.
                .map(|c| if j == 0 || j == 2 { c } else { -c })
        })
    })
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
            let p2 = elligator_squared_to_point(&u, &v).expect("should have decoded");

            assert_eq!(p, p2);
        }
    }
}
