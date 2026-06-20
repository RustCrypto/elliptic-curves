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

mod wnaf;

use super::{
    ProjectivePoint,
    scalar::{Scalar, WideScalar},
};
use core::array;
use elliptic_curve::{
    array::sizes::{U5, U33, U257},
    ops::{LinearCombination, Mul, MulAssign, MulByGeneratorVartime, MulVartime},
    scalar::IsHigh,
    subtle::ConditionallySelectable,
};
use primeorder::{PrimeFieldExt, Radix16Decomposition};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "precomputed-tables")]
use {super::tables::BASEPOINT_TABLE, elliptic_curve::array::sizes::U65};

/// Lookup table for multiples of a given point.
type LookupTable = primeorder::LookupTable<ProjectivePoint>;

/// `WnafBase` specialized for `k256`.
type WnafBase = wnaf::WnafBase<ProjectivePoint, U5>;

/// `WnafScalar` specialized for `k256`.
type WnafScalar = wnaf::WnafScalar<Scalar, U5, U257>;

const MINUS_LAMBDA: Scalar = Scalar::from_bytes_unchecked(&[
    0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed, 0x9b, 0xa4,
    0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10, 0xb5, 0x12, 0x83, 0xcf,
]);

const MINUS_B1: Scalar = Scalar::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
]);

const MINUS_B2: Scalar = Scalar::from_bytes_unchecked(&[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8, 0x3d, 0xb1, 0x56, 0x2c,
]);

const G1: Scalar = Scalar::from_bytes_unchecked(&[
    0x30, 0x86, 0xd2, 0x21, 0xa7, 0xd4, 0x6b, 0xcd, 0xe8, 0x6c, 0x90, 0xe4, 0x92, 0x84, 0xeb, 0x15,
    0x3d, 0xaa, 0x8a, 0x14, 0x71, 0xe8, 0xca, 0x7f, 0xe8, 0x93, 0x20, 0x9a, 0x45, 0xdb, 0xb0, 0x31,
]);

const G2: Scalar = Scalar::from_bytes_unchecked(&[
    0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e, 0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc4,
    0x22, 0x12, 0x08, 0xac, 0x9d, 0xf5, 0x06, 0xc6, 0x15, 0x71, 0xb4, 0xae, 0x8a, 0xc4, 0x7f, 0x71,
]);

/// Number of little-endian bytes to feed into `WnafScalar::from_le_bytes` for a GLV half-scalar.
/// GLV guarantees magnitude < 2^128 (16 bytes).
const GLV_LE_BYTES: usize = 16;

/*
 * Proof for decompose_scalar's bounds.
 *
 * Let
 *  - epsilon1 = 2^256 * |g1/2^384 - b2/d|
 *  - epsilon2 = 2^256 * |g2/2^384 - (-b1)/d|
 *  - c1 = round(k*g1/2^384)
 *  - c2 = round(k*g2/2^384)
 *
 * Lemma 1: |c1 - k*b2/d| < 2^-1 + epsilon1
 *
 *    |c1 - k*b2/d|
 *  =
 *    |c1 - k*g1/2^384 + k*g1/2^384 - k*b2/d|
 * <=   {triangle inequality}
 *    |c1 - k*g1/2^384| + |k*g1/2^384 - k*b2/d|
 *  =
 *    |c1 - k*g1/2^384| + k*|g1/2^384 - b2/d|
 * <    {rounding in c1 and 0 <= k < 2^256}
 *    2^-1 + 2^256 * |g1/2^384 - b2/d|
 *  =   {definition of epsilon1}
 *    2^-1 + epsilon1
 *
 * Lemma 2: |c2 - k*(-b1)/d| < 2^-1 + epsilon2
 *
 *    |c2 - k*(-b1)/d|
 *  =
 *    |c2 - k*g2/2^384 + k*g2/2^384 - k*(-b1)/d|
 * <=   {triangle inequality}
 *    |c2 - k*g2/2^384| + |k*g2/2^384 - k*(-b1)/d|
 *  =
 *    |c2 - k*g2/2^384| + k*|g2/2^384 - (-b1)/d|
 * <    {rounding in c2 and 0 <= k < 2^256}
 *    2^-1 + 2^256 * |g2/2^384 - (-b1)/d|
 *  =   {definition of epsilon2}
 *    2^-1 + epsilon2
 *
 * Let
 *  - k1 = k - c1*a1 - c2*a2
 *  - k2 = - c1*b1 - c2*b2
 *
 * Lemma 3: |k1| < (a1 + a2 + 1)/2 < 2^128
 *
 *    |k1|
 *  =   {definition of k1}
 *    |k - c1*a1 - c2*a2|
 *  =   {(a1*b2 - b1*a2)/n = 1}
 *    |k*(a1*b2 - b1*a2)/n - c1*a1 - c2*a2|
 *  =
 *    |a1*(k*b2/n - c1) + a2*(k*(-b1)/n - c2)|
 * <=   {triangle inequality}
 *    a1*|k*b2/n - c1| + a2*|k*(-b1)/n - c2|
 * <    {Lemma 1 and Lemma 2}
 *    a1*(2^-1 + epsilon1) + a2*(2^-1 + epsilon2)
 * <    {rounding up to an integer}
 *    (a1 + a2 + 1)/2
 * <    {rounding up to a power of 2}
 *    2^128
 *
 * Lemma 4: |k2| < (-b1 + b2)/2 + 1 < 2^128
 *
 *    |k2|
 *  =   {definition of k2}
 *    |- c1*a1 - c2*a2|
 *  =   {(b1*b2 - b1*b2)/n = 0}
 *    |k*(b1*b2 - b1*b2)/n - c1*b1 - c2*b2|
 *  =
 *    |b1*(k*b2/n - c1) + b2*(k*(-b1)/n - c2)|
 * <=   {triangle inequality}
 *    (-b1)*|k*b2/n - c1| + b2*|k*(-b1)/n - c2|
 * <    {Lemma 1 and Lemma 2}
 *    (-b1)*(2^-1 + epsilon1) + b2*(2^-1 + epsilon2)
 * <    {rounding up to an integer}
 *    (-b1 + b2)/2 + 1
 * <    {rounding up to a power of 2}
 *    2^128
 *
 * Let
 *  - r2 = k2 mod n
 *  - r1 = k - r2*lambda mod n.
 *
 * Notice that r1 is defined such that r1 + r2 * lambda == k (mod n).
 *
 * Lemma 5: r1 == k1 mod n.
 *
 *    r1
 * ==   {definition of r1 and r2}
 *    k - k2*lambda
 * ==   {definition of k2}
 *    k - (- c1*b1 - c2*b2)*lambda
 * ==
 *    k + c1*b1*lambda + c2*b2*lambda
 * ==  {a1 + b1*lambda == 0 mod n and a2 + b2*lambda == 0 mod n}
 *    k - c1*a1 - c2*a2
 * ==  {definition of k1}
 *    k1
 *
 * From Lemma 3, Lemma 4, Lemma 5 and the definition of r2, we can conclude that
 *
 *  - either r1 < 2^128 or -r1 mod n < 2^128
 *  - either r2 < 2^128 or -r2 mod n < 2^128.
 *
 * Q.E.D.
 */

/// Find r1 and r2 given k, such that r1 + r2 * lambda == k mod n.
fn decompose_scalar(k: &Scalar) -> (Scalar, Scalar) {
    // these _vartime calls are constant time since the shift amount is constant
    let c1 = WideScalar::mul_shift_vartime(k, &G1, 384) * MINUS_B1;
    let c2 = WideScalar::mul_shift_vartime(k, &G2, 384) * MINUS_B2;
    let r2 = c1 + c2;
    let r1 = k + r2 * MINUS_LAMBDA;

    (r1, r2)
}

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
            decompose_glv_wnaf(x, k)
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
            .map(|(x, k)| decompose_glv_wnaf(x, k))
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
        let (r1, r2) = decompose_scalar(k);
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
            acc = acc.double();
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
/// (using `decompose_glv_wnaf`) in combination with w-NAF scalar multiplication.
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
                acc2 = acc2.double();
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
                acc2 = acc2.double();
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
    lincomb_vartime_glv_wnaf(&[decompose_glv_wnaf(x, k)])
}

/// GLV-decompose `k` for `x`: two `(WnafBase, WnafScalar)` pairs representing `r1 * self_signed`
/// and `r2 * endomorphism(self_signed)`, with signs folded into the points.
fn decompose_glv_wnaf(x: &ProjectivePoint, k: &Scalar) -> ([WnafBase; 2], [WnafScalar; 2]) {
    let (r1, r2) = decompose_scalar(k);
    let r1_neg = bool::from(r1.is_high());
    let r2_neg = bool::from(r2.is_high());
    let r1 = if r1_neg { -r1 } else { r1 };
    let r2 = if r2_neg { -r2 } else { r2 };

    let p1 = if r1_neg { -*x } else { *x };
    let p_beta = x.endomorphism();
    let p2 = if r2_neg { -p_beta } else { p_beta };

    let bases = [WnafBase::new(p1), WnafBase::new(p2)];

    // GLV guarantees each half-scalar fits in `GLV_LE_BYTES`, so the truncated little-endian
    // encoding round-trips and `from_le_bytes`'s canonical-range check always succeeds.
    //
    // Should that invariant ever fail to hold, fall back to the full-width `new` rather than
    // panicking; it produces an identical (just slower) result for any in-range scalar.
    let scalars = [
        WnafScalar::from_le_bytes(&r1.to_le_repr()[..GLV_LE_BYTES])
            .unwrap_or_else(|| WnafScalar::new(&r1)),
        WnafScalar::from_le_bytes(&r2.to_le_repr()[..GLV_LE_BYTES])
            .unwrap_or_else(|| WnafScalar::new(&r2)),
    ];
    (bases, scalars)
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
            decompose_glv_wnaf(&ProjectivePoint::GENERATOR, a),
            decompose_glv_wnaf(p, b),
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
