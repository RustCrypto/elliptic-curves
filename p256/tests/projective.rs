//! Projective arithmetic tests.

#![cfg(all(feature = "arithmetic", feature = "test-vectors"))]

use elliptic_curve::{
    BatchNormalize, Group,
    array::Array,
    consts::U32,
    group::{GroupEncoding, ff::PrimeField},
    ops::{LinearCombination, Reduce, ReduceNonZero},
    point::{AffineCoordinates, NonIdentity},
    sec1::{self, ToSec1Point},
};
use p256::{
    AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
    test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS},
};
use primeorder::test_projective_arithmetic;
use proptest::{prelude::*, prop_compose, proptest};

#[cfg(feature = "alloc")]
use elliptic_curve::group::Wnaf;

test_projective_arithmetic!(
    AffinePoint,
    ProjectivePoint,
    Scalar,
    ADD_TEST_VECTORS,
    MUL_TEST_VECTORS
);

#[cfg(feature = "alloc")]
#[test]
fn wnaf() {
    for (k, coords) in ADD_TEST_VECTORS.iter().enumerate() {
        let scalar = Scalar::from(k as u64 + 1);
        dbg!(&scalar, coords);

        let mut wnaf = Wnaf::new();
        let p = wnaf
            .scalar(&scalar)
            .base(ProjectivePoint::GENERATOR)
            .to_affine();
        // let mut wnaf_base = wnaf.base(ProjectivePoint::GENERATOR, 1);
        // let p = wnaf_base.scalar(&scalar).to_affine();

        let (x, _y) = (p.x(), p.y());
        assert_eq!(x.0, coords.0);
    }
}

#[test]
fn projective_identity_to_bytes() {
    // This is technically an invalid SEC1 encoding, but is preferable to panicking.
    assert_eq!([0; 33], ProjectivePoint::IDENTITY.to_bytes().as_slice());
}

prop_compose! {
    fn non_identity()(bytes in any::<[u8; 32]>()) -> NonIdentity<ProjectivePoint> {
        NonIdentity::mul_by_generator(&NonZeroScalar::reduce_nonzero(&FieldBytes::from(bytes)))
    }
}

prop_compose! {
    fn projective()(bytes in any::<[u8; 32]>()) -> ProjectivePoint {
        ProjectivePoint::mul_by_generator(&Scalar::reduce(&Array::<u8, U32>::from(bytes)))
    }
}

prop_compose! {
    fn scalar()(bytes in any::<[u8; 32]>()) -> Scalar {
        Scalar::reduce(&Array::<u8, U32>::from(bytes))
    }
}

// TODO: move to `primeorder::test_projective_arithmetic`.
proptest! {
    #[cfg(feature = "alloc")]
    #[test]
    fn wnaf_proptest(
        point in projective(),
        scalar in scalar(),
    ) {
        let result = point * scalar;
        let wnaf_result = Wnaf::new().scalar(&scalar).base(point);
        prop_assert_eq!(result.to_affine(), wnaf_result.to_affine());
    }

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

    #[test]
    fn lincomb(
        p1 in projective(),
        s1 in scalar(),
        p2 in projective(),
        s2 in scalar(),
    ) {
        let reference = p1 * s1 + p2 * s2;
        let test = ProjectivePoint::lincomb(&[(p1, s1), (p2, s2)]);
        assert_eq!(reference, test);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn lincomb_alloc(
        p1 in projective(),
        s1 in scalar(),
        p2 in projective(),
        s2 in scalar(),
    ) {
        let reference = p1 * s1 + p2 * s2;
        let test = ProjectivePoint::lincomb(vec![(p1, s1), (p2, s2)].as_slice());
        assert_eq!(reference, test);
    }
}
