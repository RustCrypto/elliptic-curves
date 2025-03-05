//! Projective arithmetic tests.

#![cfg(all(feature = "arithmetic", feature = "test-vectors"))]

use elliptic_curve::{
    group::{GroupEncoding, ff::PrimeField},
    sec1::{self, ToEncodedPoint},
};
use p256::{
    AffinePoint, ProjectivePoint, Scalar,
    test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
};
use primeorder::{Double, impl_projective_arithmetic_tests};

impl_projective_arithmetic_tests!(
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
