//! A pure-Rust implementation of group operations on secp256k1.

pub(crate) mod affine;
mod field;
#[cfg(feature = "hash2curve")]
mod hash2curve;
mod mul;
pub(crate) mod projective;
pub(crate) mod scalar;

#[cfg(test)]
mod dev;

use alloc::vec::Vec;
pub use field::FieldElement;

use self::{affine::AffinePoint, projective::ProjectivePoint, scalar::Scalar};
use crate::Secp256k1;
use elliptic_curve::ops::InvertBatch;
use elliptic_curve::{CurveArithmetic, ToAffineBatch};

impl CurveArithmetic for Secp256k1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

const CURVE_EQUATION_B_SINGLE: u32 = 7u32;

#[rustfmt::skip]
pub(crate) const CURVE_EQUATION_B: FieldElement = FieldElement::from_bytes_unchecked(&[
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, CURVE_EQUATION_B_SINGLE as u8,
]);

impl ToAffineBatch for Secp256k1 {
    fn to_affine_batch_generic<const N: usize>(
        points: &[Self::ProjectivePoint; N],
    ) -> [Self::AffinePoint; N] {
        let mut zs = [FieldElement::ONE; N];

        for i in 0..N {
            let z = points[i].z;
            if z != FieldElement::ZERO {
                // Even a single zero value will fail inversion for the entire batch.
                // Put a dummy value (above `FieldElement::ONE`) so inversion succeeds
                // and treat that case specially later-on.
                zs[i] = points[i].z;
            }
        }

        // This is safe to unwrap since we assured that all elements are non-zero
        let zs_inverses = <FieldElement as InvertBatch>::invert_batch_generic(&zs).unwrap();

        let mut affine_points = [AffinePoint::IDENTITY; N];
        for i in 0..N {
            let point = points[i];
            if point.z != FieldElement::ZERO {
                // If the `z` coordinate is non-zero, we can use it to invert;
                // otherwise it defaults to the `IDENTITY` value in initialization.
                affine_points[i] = point.to_affine_internal(zs_inverses[i])
            }
        }

        affine_points
    }

    fn to_affine_batch<B: FromIterator<Self::AffinePoint>>(points: &[Self::ProjectivePoint]) -> B {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::CURVE_EQUATION_B;
    use crate::Scalar;
    use crate::Secp256k1;
    use crate::{AffinePoint, ProjectivePoint};
    use elliptic_curve::ops::MulByGenerator;
    use elliptic_curve::Field;
    use elliptic_curve::ToAffineBatch;
    use hex_literal::hex;
    use rand_core::OsRng;

    const CURVE_EQUATION_B_BYTES: [u8; 32] =
        hex!("0000000000000000000000000000000000000000000000000000000000000007");

    #[test]
    fn verify_constants() {
        assert_eq!(CURVE_EQUATION_B.to_bytes(), CURVE_EQUATION_B_BYTES.into());
    }

    #[test]
    fn generate_secret_key() {
        use crate::SecretKey;
        use elliptic_curve::rand_core::OsRng;
        let key = SecretKey::random(&mut OsRng);

        // Sanity check
        assert!(!key.to_bytes().iter().all(|b| *b == 0))
    }

    #[test]
    fn to_affine_batch_generic() {
        let k: Scalar = Scalar::random(&mut OsRng);
        let l: Scalar = Scalar::random(&mut OsRng);
        let g = ProjectivePoint::mul_by_generator(&k);
        let h = ProjectivePoint::mul_by_generator(&l);

        let expected = [g.to_affine(), h.to_affine()];
        assert_eq!(
            <Secp256k1 as ToAffineBatch>::to_affine_batch_generic(&[g, h]),
            expected
        );

        let expected = [g.to_affine(), AffinePoint::IDENTITY];
        assert_eq!(
            <Secp256k1 as ToAffineBatch>::to_affine_batch_generic(&[g, ProjectivePoint::IDENTITY]),
            expected
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn to_affine_batch() {
        extern crate alloc;
        let k: Scalar = Scalar::random(&mut OsRng);
        let l: Scalar = Scalar::random(&mut OsRng);
        let g = ProjectivePoint::mul_by_generator(&k);
        let h = ProjectivePoint::mul_by_generator(&l);

        let expected = proptest::std_facade::vec![g.to_affine(), h.to_affine()];
        let res: alloc::vec::Vec<_> = <Secp256k1 as ToAffineBatch>::to_affine_batch(&[g, h]);
        assert_eq!(res, expected);

        let expected = proptest::std_facade::vec![g.to_affine(), AffinePoint::IDENTITY];
        let res: alloc::vec::Vec<_> =
            <Secp256k1 as ToAffineBatch>::to_affine_batch(&[g, ProjectivePoint::IDENTITY]);

        assert_eq!(res, expected);
    }
}
