//! Projective arithmetic tests.

#![cfg(all(feature = "arithmetic", feature = "test-vectors"))]

use bignp256::{
    AffinePoint, ProjectivePoint, Scalar,
    test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
};
use elliptic_curve::{
    group::{GroupEncoding, ff::PrimeField},
    ops::{LinearCombination, MulVartime},
    sec1::{self, ToSec1Point},
};
use primeorder::{Double, test_projective_arithmetic};

test_projective_arithmetic!(
    AffinePoint,
    ProjectivePoint,
    Scalar,
    ADD_TEST_VECTORS,
    MUL_TEST_VECTORS
);

#[test]
fn projective_identity_to_bytes() {
    // This is technically an invalid SEC1 encoding, but is preferable to panicking.
    assert_eq!([0; 33], ProjectivePoint::IDENTITY.to_bytes().as_slice());
}

#[test]
fn projective_vartime_scalar_multiplication() {
    let generator = ProjectivePoint::GENERATOR;

    assert_eq!(generator.mul_vartime(&Scalar::ONE), generator);
    assert_eq!(
        generator.mul_vartime(&Scalar::from(2u64)),
        generator.double()
    );
}

#[test]
fn projective_vartime_linear_combination() {
    let generator = ProjectivePoint::GENERATOR;
    let terms = [(generator, Scalar::ONE), (generator, Scalar::ONE)];

    assert_eq!(ProjectivePoint::lincomb_vartime(&terms), generator.double());
    #[cfg(feature = "alloc")]
    assert_eq!(
        ProjectivePoint::lincomb_vartime(terms.as_slice()),
        generator.double()
    );
}
