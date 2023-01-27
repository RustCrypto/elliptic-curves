//! Projective arithmetic tests.

#![cfg(all(feature = "arithmetic", feature = "test-vectors"))]

use elliptic_curve::{
    sec1::{self, ToEncodedPoint},
    PrimeField,
};
use p384::{
    test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
    AffinePoint, ProjectivePoint, Scalar,
};
use primeorder::Double;

/// Assert that the provided projective point matches the given test vector.
// TODO(tarcieri): use coordinate APIs. See zkcrypto/group#30
macro_rules! assert_point_eq {
    ($actual:expr, $expected:expr) => {
        let (expected_x, expected_y) = $expected;

        let point = $actual.to_affine().to_encoded_point(false);
        let (actual_x, actual_y) = match point.coordinates() {
            sec1::Coordinates::Uncompressed { x, y } => (x, y),
            _ => unreachable!(),
        };

        assert_eq!(&expected_x, actual_x.as_slice());
        assert_eq!(&expected_y, actual_y.as_slice());
    };
}

#[test]
fn affine_to_projective() {
    let basepoint_affine = AffinePoint::GENERATOR;
    let basepoint_projective = ProjectivePoint::GENERATOR;

    assert_eq!(
        ProjectivePoint::from(basepoint_affine),
        basepoint_projective,
    );
    assert_eq!(basepoint_projective.to_affine(), basepoint_affine);
    assert!(!bool::from(basepoint_projective.to_affine().is_identity()));
    assert!(bool::from(
        ProjectivePoint::IDENTITY.to_affine().is_identity()
    ));
}

#[test]
fn projective_identity_addition() {
    let identity = ProjectivePoint::IDENTITY;
    let generator = ProjectivePoint::GENERATOR;

    assert_eq!(identity + &generator, generator);
    assert_eq!(generator + &identity, generator);
}

#[test]
fn test_vector_repeated_add() {
    let generator = ProjectivePoint::GENERATOR;
    let mut p = generator;

    for i in 0..ADD_TEST_VECTORS.len() {
        assert_point_eq!(p, ADD_TEST_VECTORS[i]);
        p += &generator;
    }
}

#[test]
fn test_vector_repeated_add_mixed() {
    let generator = AffinePoint::GENERATOR;
    let mut p = ProjectivePoint::GENERATOR;

    for i in 0..ADD_TEST_VECTORS.len() {
        assert_point_eq!(p, ADD_TEST_VECTORS[i]);
        p += &generator;
    }
}

#[test]
fn test_vector_add_mixed_identity() {
    let generator = ProjectivePoint::GENERATOR;
    let p0 = generator + ProjectivePoint::IDENTITY;
    let p1 = generator + AffinePoint::IDENTITY;
    assert_eq!(p0, p1);
}

#[test]
fn test_vector_double_generator() {
    let generator = ProjectivePoint::GENERATOR;
    let mut p = generator;

    for i in 0..2 {
        assert_point_eq!(p, ADD_TEST_VECTORS[i]);
        p = p.double();
    }
}

#[test]
fn projective_add_vs_double() {
    let generator = ProjectivePoint::GENERATOR;
    assert_eq!(generator + &generator, generator.double());
}

#[test]
fn projective_add_and_sub() {
    let basepoint_affine = AffinePoint::GENERATOR;
    let basepoint_projective = ProjectivePoint::GENERATOR;

    assert_eq!(
        (basepoint_projective + &basepoint_projective) - &basepoint_projective,
        basepoint_projective
    );
    assert_eq!(
        (basepoint_projective + &basepoint_affine) - &basepoint_affine,
        basepoint_projective
    );
}

#[test]
fn projective_double_and_sub() {
    let generator = ProjectivePoint::GENERATOR;
    assert_eq!(generator.double() - &generator, generator);
}

#[test]
fn test_vector_scalar_mult() {
    let generator = ProjectivePoint::GENERATOR;

    for (k, coords) in ADD_TEST_VECTORS
        .iter()
        .enumerate()
        .map(|(k, coords)| (Scalar::from(k as u64 + 1), *coords))
        .chain(
            MUL_TEST_VECTORS
                .iter()
                .cloned()
                .map(|(k, x, y)| (Scalar::from_repr(k.into()).unwrap(), (x, y))),
        )
    {
        let p = generator * &k;
        assert_point_eq!(p, coords);
    }
}
