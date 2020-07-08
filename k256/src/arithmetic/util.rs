//! Helper functions.

#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};
#[cfg(test)]
use num_traits::cast::ToPrimitive;

/// Computes a - (b + borrow), returning the result along with the new borrow.
#[cfg(not(feature = "scalar-32bit"))]
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

#[cfg(feature = "scalar-32bit")]
#[inline(always)]
pub const fn sbb32(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let ret = (a as u64).wrapping_sub((b as u64) + ((borrow >> 31) as u64));
    (ret as u32, (ret >> 32) as u32)
}

#[cfg(test)]
#[allow(dead_code)]
pub fn u64_array_to_biguint(words: &[u64; 4]) -> BigUint {
    words
        .iter()
        .enumerate()
        .map(|(i, w)| w.to_biguint().unwrap() << (i * 64))
        .sum()
}

#[cfg(test)]
#[allow(dead_code)]
pub fn biguint_to_u64_array(x: &BigUint) -> [u64; 4] {
    let mask = BigUint::from(u64::MAX);
    let mut words = [0u64; 4];
    for i in 0..4 {
        words[i] = ((x >> (i * 64)) as BigUint & &mask).to_u64().unwrap();
    }
    words
}

#[cfg(test)]
#[allow(dead_code)]
pub fn u32_array_to_biguint(words: &[u32; 8]) -> BigUint {
    words
        .iter()
        .enumerate()
        .map(|(i, w)| w.to_biguint().unwrap() << (i * 32))
        .sum()
}

#[cfg(test)]
#[allow(dead_code)]
pub fn biguint_to_u32_array(x: &BigUint) -> [u32; 8] {
    let mask = BigUint::from(u32::MAX);
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = ((x >> (i * 32)) as BigUint & &mask).to_u32().unwrap();
    }
    words
}
