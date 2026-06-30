//! From libsecp256k1:
//!
//! The Secp256k1 curve has an endomorphism, where lambda * (x, y) = (beta * x, y), where
//! lambda is {0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
//!         0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72}
//!
//! "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone) gives an algorithm
//! (algorithm 3.74) to find k1 and k2 given k, such that k1 + k2 * lambda == k mod n, and k1
//! and k2 have a small size.
//! It relies on constants a1, b1, a2, b2. These constants for the value of lambda above are:
//!
//! - a1 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
//! - b1 =     -{0xe4,0x43,0x7e,0xd6,0x01,0x0e,0x88,0x28,0x6f,0x54,0x7f,0xa9,0x0a,0xbf,0xe4,0xc3}
//! - a2 = {0x01,0x14,0xca,0x50,0xf7,0xa8,0xe2,0xf3,0xf6,0x57,0xc1,0x10,0x8d,0x9d,0x44,0xcf,0xd8}
//! - b2 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
//!
//! The algorithm then computes c1 = round(b1 * k / n) and c2 = round(b2 * k / n), and gives
//! k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Instead, we use modular arithmetic, and
//! compute k1 as k - k2 * lambda, avoiding the need for constants a1 and a2.
//!
//! g1, g2 are precomputed constants used to replace division with a rounded multiplication
//! when decomposing the scalar for an endomorphism-based point multiplication.
//!
//! The possibility of using precomputed estimates is mentioned in "Guide to Elliptic Curve
//! Cryptography" (Hankerson, Menezes, Vanstone) in section 3.5.
//!
//! The derivation is described in the paper "Efficient Software Implementation of Public-Key
//! Cryptography on Sensor Networks Using the MSP430X Microcontroller" (Gouvea, Oliveira, Lopez),
//! Section 4.3 (here we use a somewhat higher-precision estimate):
//! d = a1*b2 - b1*a2
//! g1 = round((2^384)*b2/d)
//! g2 = round((2^384)*(-b1)/d)
//!
//! (Note that 'd' is also equal to the curve order here because `[a1,b1]` and `[a2,b2]` are found
//! as outputs of the Extended Euclidean Algorithm on inputs 'order' and 'lambda').

mod glv;

use super::{ProjectivePoint, scalar::Scalar};
use core::array;
use elliptic_curve::{
    array::sizes::{U5, U33},
    ops::{LinearCombination, Mul, MulAssign, MulByGeneratorVartime, MulVartime},
    scalar::IsHigh,
    subtle::ConditionallySelectable,
};
use primeorder::Radix16Decomposition;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "precomputed-tables")]
use {super::tables::BASEPOINT_TABLE, elliptic_curve::array::sizes::U65};

/// Lookup table for multiples of a given point.
type LookupTable = primeorder::LookupTable<ProjectivePoint>;

/// w-NAF window size to use by default.
type WnafWindowSize = U5;

/// `WnafBase` specialized for `k256`.
type WnafBase = wnaf::WnafBase<ProjectivePoint, WnafWindowSize>;

/// `WnafScalar` specialized for `k256`.
type WnafScalar = wnaf::WnafScalar<Scalar, WnafWindowSize>;

impl<const N: usize> LinearCombination<[(ProjectivePoint, Scalar); N]> for ProjectivePoint {
    fn lincomb(points_and_scalars: &[(ProjectivePoint, Scalar); N]) -> Self {
        let mut tables = [(LookupTable::default(), LookupTable::default()); N];
        let mut digits: [(Radix16Decomposition<U33>, Radix16Decomposition<U33>); N] =
            array::from_fn(|_| Default::default());
        lincomb(points_and_scalars, &mut tables, &mut digits)
    }

    fn lincomb_vartime(points_and_scalars: &[(ProjectivePoint, Scalar); N]) -> Self {
        let decomposed: [_; N] = array::from_fn(|i| {
            let (x, k) = &points_and_scalars[i];
            glv::decompose_wnaf(x, k)
        });

        lincomb_vartime_glv_wnaf(&decomposed)
    }
}

impl LinearCombination<[(ProjectivePoint, Scalar)]> for ProjectivePoint {
    #[cfg(feature = "alloc")]
    fn lincomb(points_and_scalars: &[(ProjectivePoint, Scalar)]) -> Self {
        let mut tables =
            vec![(LookupTable::default(), LookupTable::default()); points_and_scalars.len()];
        let mut digits = vec![
            (
                Radix16Decomposition::<U33>::default(),
                Radix16Decomposition::<U33>::default(),
            );
            points_and_scalars.len()
        ];

        lincomb(points_and_scalars, &mut tables, &mut digits)
    }

    #[cfg(feature = "alloc")]
    fn lincomb_vartime(points_and_scalars: &[(ProjectivePoint, Scalar)]) -> Self {
        let decomposed: Vec<_> = points_and_scalars
            .iter()
            .map(|(x, k)| glv::decompose_wnaf(x, k))
            .collect();

        lincomb_vartime_glv_wnaf(&decomposed)
    }
}

/// Linear combination (a.k.a. multiscalar multiplication) implemented in constant-time.
fn lincomb(
    xks: &[(ProjectivePoint, Scalar)],
    tables: &mut [(LookupTable, LookupTable)],
    digits: &mut [(Radix16Decomposition<U33>, Radix16Decomposition<U33>)],
) -> ProjectivePoint {
    xks.iter().enumerate().for_each(|(i, (x, k))| {
        let (r1, r2) = glv::decompose_scalar(k);
        let x_beta = x.endomorphism();
        let (r1_sign, r2_sign) = (r1.is_high(), r2.is_high());

        let (r1_c, r2_c) = (
            Scalar::conditional_select(&r1, &-r1, r1_sign),
            Scalar::conditional_select(&r2, &-r2, r2_sign),
        );

        tables[i] = (
            LookupTable::new(ProjectivePoint::conditional_select(x, &-*x, r1_sign)),
            LookupTable::new(ProjectivePoint::conditional_select(
                &x_beta, &-x_beta, r2_sign,
            )),
        );

        digits[i] = (
            Radix16Decomposition::<U33>::new(&r1_c),
            Radix16Decomposition::<U33>::new(&r2_c),
        )
    });

    let mut acc = ProjectivePoint::IDENTITY;
    for component in 0..xks.len() {
        let (digit1, digit2) = &digits[component];
        let (table1, table2) = tables[component];

        acc += &table1.select(digit1[32]);
        acc += &table2.select(digit2[32]);
    }

    for i in (0..32).rev() {
        for _j in 0..4 {
            acc.double_in_place();
        }

        for component in 0..xks.len() {
            let (digit1, digit2) = &digits[component];
            let (table1, table2) = tables[component];

            acc += &table1.select(digit1[i]);
            acc += &table2.select(digit2[i]);
        }
    }
    acc
}

/// Linear combination / multiscalar multiplication using inputs decomposed for the GLV endomorphism
/// (using `glv::decompose_wnaf`) in combination with w-NAF scalar multiplication.
fn lincomb_vartime_glv_wnaf(
    decomposed_xks: &[([WnafBase; 2], [WnafScalar; 2])],
) -> ProjectivePoint {
    let terms = decomposed_xks
        .iter()
        .flat_map(|(bases, scalars)| bases.iter().zip(scalars.iter()));

    WnafBase::multiscalar_mul(terms)
}

impl ProjectivePoint {
    /// Calculates `k * G`, where `G` is the generator.
    pub fn mul_by_generator(k: &Scalar) -> ProjectivePoint {
        #[cfg(feature = "precomputed-tables")]
        {
            let digits = Radix16Decomposition::<U65>::new(k);
            let table = *BASEPOINT_TABLE;
            let mut acc = table[32].select(digits[64]);
            let mut acc2 = ProjectivePoint::IDENTITY;
            for i in (0..32).rev() {
                acc2 += &table[i].select(digits[i * 2 + 1]);
                acc += &table[i].select(digits[i * 2]);
            }
            // This is the price of halving the precomputed table size (from 60kb to 30kb)
            // The performance hit is minor, about 3%.
            for _ in 0..4 {
                acc2.double_in_place();
            }
            acc + acc2
        }

        #[cfg(not(feature = "precomputed-tables"))]
        {
            ProjectivePoint::GENERATOR * k
        }
    }

    /// Calculates `k * G` in variable-time, where `G` is the generator.
    pub fn mul_by_generator_vartime(k: &Scalar) -> ProjectivePoint {
        #[cfg(feature = "precomputed-tables")]
        {
            let digits = Radix16Decomposition::<U65>::new(k);
            let table = *BASEPOINT_TABLE;
            let mut acc = table[32].select_vartime(digits[64]);
            let mut acc2 = ProjectivePoint::IDENTITY;
            for i in (0..32).rev() {
                acc2 += &table[i].select_vartime(digits[i * 2 + 1]);
                acc += &table[i].select_vartime(digits[i * 2]);
            }

            // This is the price of halving the precomputed table size (from 60kb to 30kb)
            // The performance hit is minor, about 3%.
            for _ in 0..4 {
                acc2.double_in_place();
            }

            acc + acc2
        }

        #[cfg(not(feature = "precomputed-tables"))]
        {
            ProjectivePoint::GENERATOR.mul_vartime(k)
        }
    }
}

#[inline]
fn mul(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    ProjectivePoint::lincomb(&[(*x, *k)])
}

/// Variable-time `k * self` using width-5 wNAF + GLV endomorphism.
#[inline]
fn mul_vartime(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    let mut bases = [WnafBase::default(), WnafBase::default()];
    let mut scalars = [WnafScalar::default(), WnafScalar::default()];
    glv::decompose_wnaf_into(x, k, &mut bases, &mut scalars);
    WnafBase::multiscalar_mul([(&bases[0], &scalars[0]), (&bases[1], &scalars[1])].into_iter())
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    #[inline]
    fn mul(self, other: Scalar) -> ProjectivePoint {
        mul(&self, &other)
    }
}

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    #[inline]
    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    #[inline]
    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul(&self, other)
    }
}

impl MulVartime<Scalar> for ProjectivePoint {
    #[inline]
    fn mul_vartime(self, other: Scalar) -> ProjectivePoint {
        mul_vartime(&self, &other)
    }
}

impl MulVartime<&Scalar> for &ProjectivePoint {
    #[inline]
    fn mul_vartime(self, other: &Scalar) -> ProjectivePoint {
        mul_vartime(self, other)
    }
}

impl MulVartime<&Scalar> for ProjectivePoint {
    #[inline]
    fn mul_vartime(self, other: &Scalar) -> ProjectivePoint {
        mul_vartime(&self, other)
    }
}

impl MulByGeneratorVartime for ProjectivePoint {
    #[inline]
    fn mul_by_generator_vartime(k: &Scalar) -> ProjectivePoint {
        Self::mul_by_generator_vartime(k)
    }

    fn mul_by_generator_and_mul_add_vartime(a: &Self::Scalar, b: &Self::Scalar, p: &Self) -> Self {
        let decomposed = [
            glv::decompose_wnaf(&ProjectivePoint::GENERATOR, a),
            glv::decompose_wnaf(p, b),
        ];

        lincomb_vartime_glv_wnaf(&decomposed)
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = mul(self, &rhs);
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = mul(self, rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::{ProjectivePoint, Scalar};

    #[cfg(feature = "getrandom")]
    use elliptic_curve::Generate;

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_lincomb() {
        let x = ProjectivePoint::generate();
        let y = ProjectivePoint::generate();
        let k = Scalar::generate();
        let l = Scalar::generate();

        let reference = x * k + y * l;
        let test = ProjectivePoint::lincomb(&[(x, k), (y, l)]);
        assert_eq!(reference, test);
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_mul_by_generator() {
        let k = Scalar::generate();
        let reference = ProjectivePoint::GENERATOR * k;
        let test = ProjectivePoint::mul_by_generator(&k);
        assert_eq!(reference, test);
    }

    #[test]
    fn test_mul_vartime() {
        let p = ProjectivePoint::GENERATOR;
        assert_eq!(p.mul(&Scalar::ZERO), ProjectivePoint::IDENTITY);
        assert_eq!(p.mul(&Scalar::ONE), p);
        assert_eq!(p.mul(&-Scalar::ONE), -p);
        assert_eq!(
            ProjectivePoint::IDENTITY.mul(&Scalar::ONE),
            ProjectivePoint::IDENTITY
        );
    }

    #[cfg(all(feature = "alloc", feature = "getrandom"))]
    #[test]
    fn test_lincomb_slice() {
        let x = ProjectivePoint::generate();
        let y = ProjectivePoint::generate();
        let k = Scalar::generate();
        let l = Scalar::generate();

        let reference = x * k + y * l;
        let points_and_scalars = vec![(x, k), (y, l)];

        let test = ProjectivePoint::lincomb(points_and_scalars.as_slice());
        assert_eq!(reference, test);
    }
}
