//! Projective arithmetic tests.

#![cfg(feature = "arithmetic")]

use elliptic_curve::{
    BatchNormalize,
    array::Array,
    consts::U32,
    ops::{LinearCombination, MulVartime, Reduce, ReduceNonZero},
    point::NonIdentity,
};
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, Scalar};
use proptest::{prelude::any, prop_compose, proptest};

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

proptest! {
    #[test]
    fn batch_normalize(
        a in non_identity(),
        b in non_identity(),
    ) {
        let points = [*a, *b];
        let affine_points = ProjectivePoint::batch_normalize(&points);

        for (point, affine_point) in points.into_iter().zip(affine_points) {
            assert_eq!(affine_point, point.to_affine());
        }
    }

    #[test]
    fn batch_normalize_vartime(
        a in non_identity(),
        b in non_identity(),
    ) {
        let points = [*a, *b];
        let affine_points = ProjectivePoint::batch_normalize_vartime(&points);

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
        let points = vec![*a, *b];
        let affine_points = ProjectivePoint::batch_normalize(points.as_slice());

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
        p3 in projective(),
        s3 in scalar(),
    ) {
        let reference = p1 * s1 + p2 * s2 + p3 * s3;
        let test = ProjectivePoint::lincomb(&[(p1, s1), (p2, s2), (p3, s3)]);
        assert_eq!(reference, test);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn lincomb_alloc(
        p1 in projective(),
        s1 in scalar(),
        p2 in projective(),
        s2 in scalar(),
        p3 in projective(),
        s3 in scalar(),
    ) {
        let reference = p1 * s1 + p2 * s2 + p3 * s3;
        let test = ProjectivePoint::lincomb(vec![(p1, s1), (p2, s2), (p3, s3)].as_slice());
        assert_eq!(reference, test);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn lincomb_vartime(
        p1 in projective(),
        s1 in scalar(),
        p2 in projective(),
        s2 in scalar(),
        p3 in projective(),
        s3 in scalar(),
    ) {
        let reference = p1 * s1 + p2 * s2 + p3 * s3;
        let test = ProjectivePoint::lincomb_vartime(vec![(p1, s1), (p2, s2), (p3, s3)].as_slice());
        assert_eq!(reference, test);
    }

    /// Exercises the bucketed Pippenger path. Every other lincomb test here is 3-term, so none
    /// of them reach it.
    ///
    /// The size range is above the current dispatch threshold, so `lincomb_vartime` selects
    /// Pippenger. The unit tests in `arithmetic::mul::pippenger` cover the threshold itself,
    /// relative to the constant, so raising it cannot silently take this range back to w-NAF
    /// without those failing.
    #[test]
    #[cfg(feature = "alloc")]
    fn lincomb_vartime_large(
        pairs in proptest::collection::vec((projective(), scalar()), 140..150),
    ) {
        let reference = pairs
            .iter()
            .fold(ProjectivePoint::IDENTITY, |acc, (p, s)| acc + *p * *s);

        assert_eq!(reference, ProjectivePoint::lincomb_vartime(pairs.as_slice()));
        assert_eq!(reference, ProjectivePoint::lincomb(pairs.as_slice()));
    }

    #[test]
    fn mul_by_generator(s1 in scalar()) {
        let reference = ProjectivePoint::GENERATOR * s1;
        let test = ProjectivePoint::mul_by_generator(&s1);
        assert_eq!(reference, test);
    }

    #[test]
    fn mul_by_generator_vartime(s1 in scalar()) {
        let reference = ProjectivePoint::GENERATOR * s1;
        let test = ProjectivePoint::mul_by_generator_vartime(&s1);
        assert_eq!(reference, test);
    }

    #[test]
    fn mul_vartime(
        p1 in projective(),
        s1 in scalar()
    ) {
        let reference = p1 * s1;
        let test = p1.mul_vartime(&s1);
        assert_eq!(reference, test);
    }
}
