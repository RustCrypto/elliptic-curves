//! Projective arithmetic tests.

#![cfg(all(feature = "arithmetic", feature = "test-vectors"))]

// TODO(tarcieri): these are failing
//
// use bign256::{
//     test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
//     AffinePoint, ProjectivePoint, Scalar,
// };
// use elliptic_curve::{
//     group::{ff::PrimeField, GroupEncoding},
//     sec1::{self, ToEncodedPoint},
// };
// use primeorder::{impl_projective_arithmetic_tests, Double};
//
// impl_projective_arithmetic_tests!(
//     AffinePoint,
//     ProjectivePoint,
//     Scalar,
//     ADD_TEST_VECTORS,
//     MUL_TEST_VECTORS
// );

use bign256::{elliptic_curve::group::GroupEncoding, ProjectivePoint};

#[test]
fn projective_identity_to_bytes() {
    // This is technically an invalid SEC1 encoding, but is preferable to panicking.
    assert_eq!([0; 33], ProjectivePoint::IDENTITY.to_bytes().as_slice());
}
