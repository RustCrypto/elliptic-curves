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
pub fn u64_array_to_biguint(words: &[u64; 4]) -> BigUint {
    words[0].to_biguint().unwrap()
        + (words[1].to_biguint().unwrap() << 64)
        + (words[2].to_biguint().unwrap() << 128)
        + (words[3].to_biguint().unwrap() << 192)
}

#[cfg(test)]
pub fn biguint_to_u64_array(x: &BigUint) -> [u64; 4] {
    let mask = BigUint::from(u64::MAX);
    let w0 = (x & &mask).to_u64().unwrap();
    let w1 = ((x >> 64) as BigUint & &mask).to_u64().unwrap();
    let w2 = ((x >> 128) as BigUint & &mask).to_u64().unwrap();
    let w3 = ((x >> 192) as BigUint & &mask).to_u64().unwrap();
    [w0, w1, w2, w3]
}

#[cfg(test)]
pub fn u32_array_to_biguint(words: &[u32; 8]) -> BigUint {
    words[0].to_biguint().unwrap()
        + (words[1].to_biguint().unwrap() << 32)
        + (words[2].to_biguint().unwrap() << 64)
        + (words[3].to_biguint().unwrap() << 96)
        + (words[4].to_biguint().unwrap() << 128)
        + (words[5].to_biguint().unwrap() << 160)
        + (words[6].to_biguint().unwrap() << 192)
        + (words[7].to_biguint().unwrap() << 224)
}

#[cfg(test)]
pub fn biguint_to_u32_array(x: &BigUint) -> [u32; 8] {
    let mask = BigUint::from(u32::MAX);
    let w0 = (x & &mask).to_u32().unwrap();
    let w1 = ((x >> 32) as BigUint & &mask).to_u32().unwrap();
    let w2 = ((x >> 64) as BigUint & &mask).to_u32().unwrap();
    let w3 = ((x >> 96) as BigUint & &mask).to_u32().unwrap();
    let w4 = ((x >> 128) as BigUint & &mask).to_u32().unwrap();
    let w5 = ((x >> 160) as BigUint & &mask).to_u32().unwrap();
    let w6 = ((x >> 192) as BigUint & &mask).to_u32().unwrap();
    let w7 = ((x >> 224) as BigUint & &mask).to_u32().unwrap();

    [w0, w1, w2, w3, w4, w5, w6, w7]
}
