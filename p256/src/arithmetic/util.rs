//! Helper functions.
// TODO(tarcieri): replace these with `crypto-bigint`
#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};
#[cfg(test)]
use num_traits::cast::ToPrimitive;

/// Computes `a + b + carry`, returning the result along with the new carry. 64-bit version.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow. 64-bit version.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Converts a byte array (big-endian) to BigUint.
#[cfg(test)]
pub fn bytes_to_biguint(bytes: &[u8; 32]) -> BigUint {
    bytes
        .iter()
        .enumerate()
        .map(|(i, w)| w.to_biguint().unwrap() << ((31 - i) * 8))
        .sum()
}

/// Converts a BigUint to a byte array (big-endian).
#[cfg(test)]
pub fn biguint_to_bytes(x: &BigUint) -> [u8; 32] {
    let mask = BigUint::from(u8::MAX);
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = ((x >> ((31 - i) * 8)) as BigUint & &mask).to_u8().unwrap();
    }
    bytes
}
