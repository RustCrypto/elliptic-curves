//! Projective arithmetic tests.

#![cfg(all(feature = "arithmetic", feature = "test-vectors"))]

use elliptic_curve::{
    BatchNormalize,
    group::{GroupEncoding, ff::PrimeField},
    ops::ReduceNonZero,
    point::NonIdentity,
    sec1::{self, ToEncodedPoint},
};
use p256::{
    AffinePoint, NonZeroScalar, ProjectivePoint, Scalar,
    test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
};
use primeorder::{Double, test_projective_arithmetic};
use proptest::{prelude::any, prop_compose, proptest};

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

prop_compose! {
    fn non_identity()(bytes in any::<[u8; 32]>()) -> NonIdentity<ProjectivePoint> {
        NonIdentity::mul_by_generator(&NonZeroScalar::reduce_nonzero_bytes(&bytes.into()))
    }
}

// TODO: move to `primeorder::test_projective_arithmetic`.
proptest! {
    #[test]
    fn batch_normalize(
        a in non_identity(),
        b in non_identity(),
    ) {
        let points: [NonIdentity<ProjectivePoint>; 2] = [a, b];

        let affine_points = NonIdentity::batch_normalize(&points);

        for (point, affine_point) in points.into_iter().zip(affine_points) {
            assert_eq!(affine_point, point.to_affine());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn batch_normalize_alloc(
        a in non_identity(),
        b in non_identity(),
    ) {
        let points = vec![a, b];

        let affine_points = NonIdentity::batch_normalize(points.as_slice());

        for (point, affine_point) in points.into_iter().zip(affine_points) {
            assert_eq!(affine_point, point.to_affine());
        }
    }
}
