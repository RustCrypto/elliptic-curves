//! Helper functions.

/// Computes a - (b + borrow), returning the result along with the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}


pub fn verify_bits(x: u64, b: u64) -> bool {
    (x >> b) == 0
}


pub fn verify_bits_128(x: u128, b: u64) -> bool {
    (x >> b) == 0
}
