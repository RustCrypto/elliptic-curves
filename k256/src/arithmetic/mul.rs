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

use super::{
    ProjectivePoint,
    scalar::{Scalar, WideScalar},
};
use elliptic_curve::{
    ops::{LinearCombination, Mul, MulAssign, MulByGeneratorVartime, MulVartime},
    scalar::IsHigh,
    subtle::ConditionallySelectable,
};

#[cfg(feature = "precomputed-tables")]
use super::tables::BASEPOINT_TABLE;

/// Lookup table for multiples of a given point.
type LookupTable = elliptic_curve::point::LookupTable<ProjectivePoint>;

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

// This needs to be an object to have Default implemented for it
// (required because it's used in static_map later)
// Otherwise we could just have a function returning an array.
#[derive(Copy, Clone)]
struct Radix16Decomposition<const D: usize>([i8; D]);

impl<const D: usize> Radix16Decomposition<D> {
    /// Returns an object containing a decomposition
    /// `[a_0, ..., a_D]` such that `sum(a_j * 2^(j * 4)) == x`,
    /// and `-8 <= a_j <= 7`.
    /// Assumes `x < 2^(4*(D-1))`.
    fn new(x: &Scalar) -> Self {
        debug_assert!((x >> (4 * (D - 1))).is_zero().unwrap_u8() == 1);

        // The resulting decomposition can be negative, so, despite the limit on `x`,
        // we need an additional byte to store the carry.
        let mut output = [0i8; D];

        // Step 1: change radix.
        // Convert from radix 256 (bytes) to radix 16 (nibbles)
        let bytes = x.to_bytes();
        for i in 0..(D - 1) / 2 {
            output[2 * i] = (bytes[31 - i] & 0xf) as i8;
            output[2 * i + 1] = ((bytes[31 - i] >> 4) & 0xf) as i8;
        }

        // Step 2: recenter coefficients from [0,16) to [-8,8)
        for i in 0..(D - 1) {
            let carry = (output[i] + 8) >> 4;
            output[i] -= carry << 4;
            output[i + 1] += carry;
        }

        Self(output)
    }
}

impl<const D: usize> Default for Radix16Decomposition<D> {
    fn default() -> Self {
        Self([0i8; D])
    }
}

impl<const N: usize> LinearCombination<[(ProjectivePoint, Scalar); N]> for ProjectivePoint {
    fn lincomb(points_and_scalars: &[(ProjectivePoint, Scalar); N]) -> Self {
        let mut tables = [(LookupTable::default(), LookupTable::default()); N];
        let mut digits = [(
            Radix16Decomposition::<33>::default(),
            Radix16Decomposition::<33>::default(),
        ); N];

        lincomb(points_and_scalars, &mut tables, &mut digits)
    }
}

impl LinearCombination<[(ProjectivePoint, Scalar)]> for ProjectivePoint {
    #[cfg(feature = "alloc")]
    fn lincomb(points_and_scalars: &[(ProjectivePoint, Scalar)]) -> Self {
        let mut tables =
            vec![(LookupTable::default(), LookupTable::default()); points_and_scalars.len()];
        let mut digits = vec![
            (
                Radix16Decomposition::<33>::default(),
                Radix16Decomposition::<33>::default(),
            );
            points_and_scalars.len()
        ];

        lincomb(points_and_scalars, &mut tables, &mut digits)
    }
}

fn lincomb(
    xks: &[(ProjectivePoint, Scalar)],
    tables: &mut [(LookupTable, LookupTable)],
    digits: &mut [(Radix16Decomposition<33>, Radix16Decomposition<33>)],
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
            Radix16Decomposition::<33>::new(&r1_c),
            Radix16Decomposition::<33>::new(&r2_c),
        )
    });

    let mut acc = ProjectivePoint::IDENTITY;
    for component in 0..xks.len() {
        let (digit1, digit2) = digits[component];
        let (table1, table2) = tables[component];

        acc += &table1.select(digit1.0[32]);
        acc += &table2.select(digit2.0[32]);
    }

    for i in (0..32).rev() {
        for _j in 0..4 {
            acc = acc.double();
        }

        for component in 0..xks.len() {
            let (digit1, digit2) = digits[component];
            let (table1, table2) = tables[component];

            acc += &table1.select(digit1.0[i]);
            acc += &table2.select(digit2.0[i]);
        }
    }
    acc
}

/// Width of the wNAF window. Digits are odd values in `[-(2^(W-1) - 1), 2^(W-1) - 1]`.
const WNAF_WIDTH: usize = 5;

/// Number of precomputed odd multiples per point: `[P, 3P, 5P, ..., 15P]`.
const WNAF_TABLE_SIZE: usize = 1 << (WNAF_WIDTH - 2);

/// Output length for a signed-digit wNAF of a <= 129-bit value (128-bit GLV half plus a carry bit).
const WNAF_DIGITS: usize = 130;

/// Compute a width-`WNAF_WIDTH` signed-digit non-adjacent form of `k`, where `k` is known to fit
/// in 128 bits (magnitude only — sign is tracked separately by the caller). The output array has
/// one entry per bit, with zero entries meaning "skip this step". Nonzero entries are odd and in
/// `[-(2^(W-1) - 1), 2^(W-1) - 1]`.
///
/// Callers must only pass values whose magnitude is < 2^128, which is the GLV guarantee.
fn wnaf_128(k: &Scalar) -> [i8; WNAF_DIGITS] {
    // Load the low 128 bits as little-endian u64 limbs. `to_bytes` is big-endian.
    let bytes = k.to_bytes();
    let mut lo = u64::from_be_bytes(bytes[24..32].try_into().expect("8 bytes"));
    let mut hi = u64::from_be_bytes(bytes[16..24].try_into().expect("8 bytes"));

    let width_mask: u64 = (1 << WNAF_WIDTH) - 1;
    let half: u64 = 1 << (WNAF_WIDTH - 1);

    let mut out = [0i8; WNAF_DIGITS];
    let mut i = 0;
    while (lo | hi) != 0 {
        if (lo & 1) == 1 {
            // d = k mod 2^W, recentered into [-2^(W-1) + 1, 2^(W-1) - 1]
            let mut d = (lo & width_mask) as i64;
            if d >= half as i64 {
                d -= 1 << WNAF_WIDTH;
            }
            out[i] = d as i8;

            // k -= d (128-bit signed update)
            if d < 0 {
                // k -= (negative d) == k += |d|
                let add = (-d) as u64;
                let (new_lo, carry) = lo.overflowing_add(add);
                lo = new_lo;
                if carry {
                    hi = hi.wrapping_add(1);
                }
            } else {
                let sub = d as u64;
                let (new_lo, borrow) = lo.overflowing_sub(sub);
                lo = new_lo;
                if borrow {
                    hi = hi.wrapping_sub(1);
                }
            }
        }
        // Shift right by 1 across the 128-bit value.
        lo = (lo >> 1) | (hi << 63);
        hi >>= 1;
        i += 1;
    }
    out
}

/// Build `[P, 3P, 5P, ..., (2*WNAF_TABLE_SIZE - 1)P]` in projective coordinates.
fn build_odd_multiples(p: &ProjectivePoint) -> [ProjectivePoint; WNAF_TABLE_SIZE] {
    let mut out = [ProjectivePoint::IDENTITY; WNAF_TABLE_SIZE];
    let two_p = p.double();
    out[0] = *p;
    for i in 1..WNAF_TABLE_SIZE {
        out[i] = out[i - 1] + two_p;
    }
    out
}

/// Variable-time `k * P` using GLV + width-5 wNAF.
///
/// SECURITY: not constant time. Only call with non-secret scalars.
fn mul_vartime_impl(p: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    let (r1, r2) = decompose_scalar(k);
    let r1_neg = bool::from(r1.is_high());
    let r2_neg = bool::from(r2.is_high());
    let r1 = if r1_neg { -r1 } else { r1 };
    let r2 = if r2_neg { -r2 } else { r2 };

    let p1 = if r1_neg { -*p } else { *p };
    let p_beta = p.endomorphism();
    let p2 = if r2_neg { -p_beta } else { p_beta };

    let table1 = build_odd_multiples(&p1);
    let table2 = build_odd_multiples(&p2);

    let naf1 = wnaf_128(&r1);
    let naf2 = wnaf_128(&r2);

    // Find the highest nonzero digit across either NAF.
    let mut top = WNAF_DIGITS;
    while top > 0 && naf1[top - 1] == 0 && naf2[top - 1] == 0 {
        top -= 1;
    }
    if top == 0 {
        return ProjectivePoint::IDENTITY;
    }

    // Standard left-to-right double-and-add-with-signed-digits.
    let mut acc = ProjectivePoint::IDENTITY;
    for i in (0..top).rev() {
        acc = acc.double();

        let d1 = naf1[i];
        if d1 != 0 {
            let idx = ((d1.unsigned_abs()) >> 1) as usize;
            if d1 > 0 {
                acc += &table1[idx];
            } else {
                acc += &(-table1[idx]);
            }
        }

        let d2 = naf2[i];
        if d2 != 0 {
            let idx = ((d2.unsigned_abs()) >> 1) as usize;
            if d2 > 0 {
                acc += &table2[idx];
            } else {
                acc += &(-table2[idx]);
            }
        }
    }

    acc
}

impl ProjectivePoint {
    /// Calculates `k * G`, where `G` is the generator.
    #[cfg(not(feature = "precomputed-tables"))]
    pub(super) fn mul_by_generator(k: &Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * k
    }

    /// Calculates `k * G`, where `G` is the generator.
    #[cfg(feature = "precomputed-tables")]
    pub(super) fn mul_by_generator(k: &Scalar) -> ProjectivePoint {
        let digits = Radix16Decomposition::<65>::new(k);
        let table = *BASEPOINT_TABLE;
        let mut acc = table[32].select(digits.0[64]);
        let mut acc2 = ProjectivePoint::IDENTITY;
        for i in (0..32).rev() {
            acc2 += &table[i].select(digits.0[i * 2 + 1]);
            acc += &table[i].select(digits.0[i * 2]);
        }
        // This is the price of halving the precomputed table size (from 60kb to 30kb)
        // The performance hit is minor, about 3%.
        for _ in 0..4 {
            acc2 = acc2.double();
        }
        acc + acc2
    }
}

#[inline(always)]
fn mul(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    ProjectivePoint::lincomb(&[(*x, *k)])
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: Scalar) -> ProjectivePoint {
        mul(&self, &other)
    }
}

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul(&self, other)
    }
}

impl MulVartime<Scalar> for ProjectivePoint {
    fn mul_vartime(self, other: Scalar) -> ProjectivePoint {
        mul_vartime_impl(&self, &other)
    }
}

impl MulVartime<&Scalar> for &ProjectivePoint {
    fn mul_vartime(self, other: &Scalar) -> ProjectivePoint {
        mul_vartime_impl(self, other)
    }
}

impl MulVartime<&Scalar> for ProjectivePoint {
    fn mul_vartime(self, other: &Scalar) -> ProjectivePoint {
        mul_vartime_impl(&self, other)
    }
}

impl MulByGeneratorVartime for ProjectivePoint {
    fn mul_by_generator_vartime(k: &Scalar) -> ProjectivePoint {
        // The precomputed basepoint table is already constant-time fast; beating it with wNAF
        // would require a much larger vartime-specific table. When tables are unavailable,
        // fall back to the endomorphism-aware vartime mul on the generator.
        #[cfg(feature = "precomputed-tables")]
        {
            Self::mul_by_generator(k)
        }
        #[cfg(not(feature = "precomputed-tables"))]
        {
            mul_vartime_impl(&Self::GENERATOR, k)
        }
    }

    fn mul_by_generator_and_mul_add_vartime(
        a: &Self::Scalar,
        b_scalar: &Self::Scalar,
        b_point: &Self,
    ) -> Self {
        Self::mul_by_generator_vartime(a) + mul_vartime_impl(b_point, b_scalar)
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
    #[cfg(feature = "getrandom")]
    fn test_mul_vartime() {
        for _ in 0..32 {
            let p = ProjectivePoint::generate();
            let k = Scalar::generate();
            let reference = p * k;
            let test = mul_vartime_impl(&p, &k);
            assert_eq!(reference, test);
        }
    }

    #[test]
    fn test_mul_vartime_edge_cases() {
        let p = ProjectivePoint::GENERATOR;
        assert_eq!(
            mul_vartime_impl(&p, &Scalar::ZERO),
            ProjectivePoint::IDENTITY
        );
        assert_eq!(mul_vartime_impl(&p, &Scalar::ONE), p);
        assert_eq!(mul_vartime_impl(&p, &-Scalar::ONE), -p);
        assert_eq!(
            mul_vartime_impl(&ProjectivePoint::IDENTITY, &Scalar::ONE),
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
