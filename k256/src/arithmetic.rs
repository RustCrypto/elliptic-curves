//! A pure-Rust implementation of group operations on secp256k1.
//!
//! # Status
//!
//! Currently, no actual group operations are implemented. Only point compression and
//! decompression is supported.

mod field;
mod util;

#[cfg(any(feature = "test-vectors", test))]
pub mod test_vectors;

use core::convert::TryInto;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::generic_array::GenericArray;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use super::{PublicKey, Secp256k1};
use elliptic_curve::weierstrass::{CompressedCurvePoint, UncompressedCurvePoint};
use field::{FieldElement, MODULUS};

/// b = 7 in Montgomery form (aR mod p, where R = 2**256.
const CURVE_EQUATION_B: FieldElement = FieldElement([
    0x0000_0007_0000_1ab7,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

/// A point on the secp256k1 curve in affine coordinates.
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    x: FieldElement,
    y: FieldElement,
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &AffinePoint, b: &AffinePoint, choice: Choice) -> AffinePoint {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &AffinePoint) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl AffinePoint {
    /// Returns the base point of SECP256k1.
    pub fn generator() -> AffinePoint {
        // SECP256k1 basepoint in affine coordinates:
        // x = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
        // y = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
        AffinePoint {
            x: FieldElement::from_bytes([
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98,
            ])
            .unwrap(),
            y: FieldElement::from_bytes([
                0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
                0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
                0xfb, 0x10, 0xd4, 0xb8,
            ])
            .unwrap(),
        }
    }

    /// Attempts to parse the given [`PublicKey`] as an SEC-1-encoded `AffinePoint`.
    ///
    /// # Returns
    ///
    /// `None` value if `pubkey` is not on the secp256k1 curve.
    pub fn from_pubkey(pubkey: &PublicKey) -> CtOption<Self> {
        match pubkey {
            PublicKey::Compressed(point) => {
                let bytes = point.as_bytes();

                let y_is_odd = Choice::from(bytes[0] & 0x01);
                let x = FieldElement::from_bytes(bytes[1..33].try_into().unwrap());

                x.and_then(|x| {
                    let alpha = (x * &x * &x) + &CURVE_EQUATION_B;
                    let beta = alpha.sqrt();

                    beta.map(|beta| {
                        let y = FieldElement::conditional_select(
                            &(MODULUS - &beta),
                            &beta,
                            // beta.is_odd() == y_is_odd
                            !(beta.is_odd() ^ y_is_odd),
                        );

                        AffinePoint { x, y }
                    })
                })
            }
            PublicKey::Uncompressed(point) => {
                let bytes = point.as_bytes();

                let x = FieldElement::from_bytes(bytes[1..33].try_into().unwrap());
                let y = FieldElement::from_bytes(bytes[33..65].try_into().unwrap());

                x.and_then(|x| {
                    y.and_then(|y| {
                        // Check that the point is on the curve
                        let lhs = y * &y;
                        let rhs = x * &x * &x + &CURVE_EQUATION_B;
                        CtOption::new(AffinePoint { x, y }, lhs.ct_eq(&rhs))
                    })
                })
            }
        }
    }

    /// Returns the SEC-1 compressed encoding of this point.
    pub fn to_compressed_pubkey(&self) -> CompressedCurvePoint<Secp256k1> {
        let mut encoded = [0; 33];
        encoded[0] = if self.y.is_odd().into() { 0x03 } else { 0x02 };
        encoded[1..33].copy_from_slice(&self.x.to_bytes());

        CompressedCurvePoint::from_bytes(GenericArray::clone_from_slice(&encoded[..]))
            .expect("we encoded it correctly")
    }

    /// Returns the SEC-1 uncompressed encoding of this point.
    pub fn to_uncompressed_pubkey(&self) -> UncompressedCurvePoint<Secp256k1> {
        let mut encoded = [0; 65];
        encoded[0] = 0x04;
        encoded[1..33].copy_from_slice(&self.x.to_bytes());
        encoded[33..65].copy_from_slice(&self.y.to_bytes());

        UncompressedCurvePoint::from_bytes(GenericArray::clone_from_slice(&encoded[..]))
            .expect("we encoded it correctly")
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    fn neg(self) -> Self::Output {
        AffinePoint {
            x: self.x,
            y: -self.y,
        }
    }
}

/// A point on the secp256k1 curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(p: AffinePoint) -> Self {
        ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::one(),
        }
    }
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ProjectivePoint {
    /// Returns the additive identity of SECP256k1, also known as the "neutral element" o
    /// "point at infinity".
    pub const fn identity() -> ProjectivePoint {
        ProjectivePoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Returns the base point of SECP256k1.
    pub fn generator() -> ProjectivePoint {
        AffinePoint::generator().into()
    }

    /// Returns the affine representation of this point, or `None` if it is the identity.
    pub fn to_affine(&self) -> CtOption<AffinePoint> {
        self.z.invert().map(|zinv| AffinePoint {
            x: self.x * &zinv,
            y: self.y * &zinv,
        })
    }

    /// Returns `-self`.
    fn neg(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Returns `self + other`.
    fn add(&self, other: &ProjectivePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 7).

        let xx = self.x * &other.x;
        let yy = self.y * &other.y;
        let zz = self.z * &other.z;
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy);
        let yz_pairs = ((self.y + &self.z) * &(other.y + &other.z)) - &(yy + &zz);
        let xz_pairs = ((self.x + &self.z) * &(other.x + &other.z)) - &(xx + &zz);

        let bzz = CURVE_EQUATION_B * &zz;
        let bzz3 = bzz.double() + &bzz;

        let yy_m_bzz3 = yy - &bzz3;
        let yy_p_bzz3 = yy + &bzz3;

        let byz = CURVE_EQUATION_B * &yz_pairs;
        let byz3 = byz.double() + &byz;

        let xx3 = xx.double() + &xx;
        let bxx9 = CURVE_EQUATION_B * &(xx3.double() + &xx3);

        ProjectivePoint {
            x: (xy_pairs * &yy_m_bzz3) - &(byz3 * &xz_pairs),
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(bxx9 * &xz_pairs),
            z: (yz_pairs * &yy_p_bzz3) + &(xx3 * &xy_pairs),
        }
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 8). The comments after each line
        // indicate which algorithm steps are being performed.
        todo!("Implement this.");
    }

    /// Doubles this point.
    fn double(&self) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 9). The comments after each line
        // indicate which algorithm steps are being performed.
        todo!("Implement this.");
    }

    /// Returns `self - other`.
    fn sub(&self, other: &ProjectivePoint) -> ProjectivePoint {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        self.add_mixed(&other.neg())
    }
}

impl Add<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(self, other)
    }
}

impl Add<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, other)
    }
}

impl AddAssign<ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl AddAssign<&ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl Add<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl Add<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl AddAssign<AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl Sub<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(self, other)
    }
}

impl Sub<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, other)
    }
}

impl SubAssign<ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl SubAssign<&ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl Sub<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl Sub<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl SubAssign<AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

//impl Mul<&scalar::Scalar> for &ProjectivePoint {
//    type Output = ProjectivePoint;
//
//    fn mul(self, other: &scalar::Scalar) -> ProjectivePoint {
//        ProjectivePoint::mul(self, other)
//    }
//}
//
//impl Mul<&scalar::Scalar> for ProjectivePoint {
//    type Output = ProjectivePoint;
//
//    fn mul(self, other: &scalar::Scalar) -> ProjectivePoint {
//        ProjectivePoint::mul(&self, other)
//    }
//}
//
//impl MulAssign<scalar::Scalar> for ProjectivePoint {
//    fn mul_assign(&mut self, rhs: scalar::Scalar) {
//        *self = ProjectivePoint::mul(self, &rhs);
//    }
//}
//
//impl MulAssign<&scalar::Scalar> for ProjectivePoint {
//    fn mul_assign(&mut self, rhs: &scalar::Scalar) {
//        *self = ProjectivePoint::mul(self, rhs);
//    }
//}

impl Neg for ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(&self)
    }
}

impl<'a> Neg for &'a ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(self)
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;

    use super::{AffinePoint, ProjectivePoint, CURVE_EQUATION_B};
    use crate::{
        arithmetic::test_vectors::group::{ADD_TEST_VECTORS},
        PublicKey,
    };

    const CURVE_EQUATION_B_BYTES: &str =
        "0000000000000000000000000000000000000000000000000000000000000007";

    const UNCOMPRESSED_BASEPOINT: &str =
        "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    const COMPRESSED_BASEPOINT: &str =
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    #[test]
    fn verify_constants() {
        assert_eq!(
            hex::encode(CURVE_EQUATION_B.to_bytes()).to_uppercase(),
            CURVE_EQUATION_B_BYTES
        );
    }

    #[test]
    fn uncompressed_round_trip() {
        let pubkey = PublicKey::from_bytes(&hex::decode(UNCOMPRESSED_BASEPOINT).unwrap()).unwrap();
        let res: PublicKey = AffinePoint::from_pubkey(&pubkey)
            .unwrap()
            .to_uncompressed_pubkey()
            .into();

        assert_eq!(res, pubkey);
    }

    #[test]
    fn compressed_round_trip() {
        let pubkey = PublicKey::from_bytes(&hex::decode(COMPRESSED_BASEPOINT).unwrap()).unwrap();
        let res: PublicKey = AffinePoint::from_pubkey(&pubkey)
            .unwrap()
            .to_compressed_pubkey()
            .into();

        assert_eq!(res, pubkey);
    }

    #[test]
    fn uncompressed_to_compressed() {
        let encoded = PublicKey::from_bytes(&hex::decode(UNCOMPRESSED_BASEPOINT).unwrap()).unwrap();

        let res = AffinePoint::from_pubkey(&encoded)
            .unwrap()
            .to_compressed_pubkey();

        assert_eq!(
            hex::encode(res.as_bytes()).to_uppercase(),
            COMPRESSED_BASEPOINT
        );
    }

    #[test]
    fn compressed_to_uncompressed() {
        let encoded = PublicKey::from_bytes(&hex::decode(COMPRESSED_BASEPOINT).unwrap()).unwrap();

        let res = AffinePoint::from_pubkey(&encoded)
            .unwrap()
            .to_uncompressed_pubkey();

        assert_eq!(
            hex::encode(res.as_bytes()).to_uppercase(),
            UNCOMPRESSED_BASEPOINT
        );
    }

    #[test]
    fn affine_negation() {
        let basepoint = AffinePoint::generator();

        assert_eq!(-(-basepoint), basepoint);
    }

    #[test]
    fn affine_to_projective() {
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

        assert_eq!(
            ProjectivePoint::from(basepoint_affine),
            basepoint_projective,
        );
        assert_eq!(basepoint_projective.to_affine().unwrap(), basepoint_affine);

        // The projective identity does not have an affine representation.
        assert!(bool::from(
            ProjectivePoint::identity().to_affine().is_none()
        ));
    }

    #[test]
    fn projective_identity_addition() {
        let identity = ProjectivePoint::identity();
        let generator = ProjectivePoint::generator();

        assert_eq!(identity + &generator, generator);
        assert_eq!(generator + &identity, generator);
    }

    #[test]
    fn projective_mixed_addition() {
        let identity = ProjectivePoint::identity();
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

        assert_eq!(identity + &basepoint_affine, basepoint_projective);
        assert_eq!(
            basepoint_projective + &basepoint_affine,
            basepoint_projective + &basepoint_projective
        );
    }

    #[test]
    fn test_vector_repeated_add() {
        let generator = ProjectivePoint::generator();
        let mut p = generator;

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(affine.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(affine.y.to_bytes()).to_uppercase().as_str(),
                ),
                ADD_TEST_VECTORS[i]
            );

            p = p + &generator;
        }
    }

    #[test]
    fn test_vector_repeated_add_mixed() {
        let generator = AffinePoint::generator();
        let mut p = ProjectivePoint::generator();

        for i in 0..ADD_TEST_VECTORS.len() {
            let affine = p.to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(affine.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(affine.y.to_bytes()).to_uppercase().as_str(),
                ),
                ADD_TEST_VECTORS[i]
            );

            p = p + &generator;
        }
    }

    #[test]
    fn test_vector_double_generator() {
        let generator = ProjectivePoint::generator();
        let mut p = generator;

        for i in 0..2 {
            let affine = p.to_affine().unwrap();
            assert_eq!(
                (
                    hex::encode(affine.x.to_bytes()).to_uppercase().as_str(),
                    hex::encode(affine.y.to_bytes()).to_uppercase().as_str(),
                ),
                ADD_TEST_VECTORS[i]
            );

            p = p.double();
        }
    }

    #[test]
    fn projective_add_vs_double() {
        let generator = ProjectivePoint::generator();

        assert_eq!(generator + &generator, generator.double());
    }

    #[test]
    fn projective_add_and_sub() {
        let basepoint_affine = AffinePoint::generator();
        let basepoint_projective = ProjectivePoint::generator();

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
        let generator = ProjectivePoint::generator();

        assert_eq!(generator.double() - &generator, generator);
    }

    //#[test]
    //fn test_vector_scalar_mult() {
    //    let generator = ProjectivePoint::generator();

    //    for (k, coords) in ADD_TEST_VECTORS
    //        .iter()
    //        .enumerate()
    //        .map(|(k, coords)| (Scalar::from(k as u64 + 1), *coords))
    //        .chain(MUL_TEST_VECTORS.iter().cloned().map(|(k, x, y)| {
    //            (
    //                Scalar::from_bytes(hex::decode(k).unwrap()[..].try_into().unwrap()).unwrap(),
    //                (x, y),
    //            )
    //        }))
    //    {
    //        let res = (generator * &k).to_affine().unwrap();
    //        assert_eq!(
    //            (
    //                hex::encode(res.x.to_bytes()).to_uppercase().as_str(),
    //                hex::encode(res.y.to_bytes()).to_uppercase().as_str(),
    //            ),
    //            coords,
    //        );
    //    }
    //}

}
