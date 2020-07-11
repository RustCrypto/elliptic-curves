//! Helper functions.

#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};
#[cfg(test)]
use num_traits::cast::ToPrimitive;

/// Computes a - (b + borrow), returning the result along with the new borrow.
#[cfg(any(feature = "scalar-4x64", feature = "field-montgomery"))]
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

#[cfg(feature = "scalar-8x32")]
#[inline(always)]
pub const fn sbb32(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let ret = (a as u64).wrapping_sub((b as u64) + ((borrow >> 31) as u64));
    (ret as u32, (ret >> 32) as u32)
}

#[cfg(any(feature = "scalar-4x64", feature = "field-montgomery"))]
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

#[cfg(feature = "scalar-8x32")]
#[inline(always)]
pub const fn adc32(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let ret = (a as u64) + (b as u64) + (carry as u64);
    (ret as u32, (ret >> 32) as u32)
}

/// Computes a + (b * c) + carry, returning the result along with the new carry.
#[cfg(feature = "field-montgomery")]
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Computes a multiply and carry via a shift and subtraction for the max of a type.
#[cfg(feature = "field-montgomery")]
#[inline(always)]
pub const fn mac_typemax(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (((b as u128) << 64) - (b as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
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
