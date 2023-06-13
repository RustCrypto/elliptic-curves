//! Helper functions.
// TODO(tarcieri): replace these with `crypto-bigint`

use elliptic_curve::bigint::U256;

/// Computes `a + b + carry`, returning the result along with the new carry. 64-bit version.
#[inline(always)]
pub(crate) const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow. 64-bit version.
#[inline(always)]
pub(crate) const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
#[inline(always)]
pub(crate) const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Array containing 4 x 64-bit unsigned integers.
// TODO(tarcieri): replace this entirely with `U256`
pub(crate) type U64x4 = [u64; 4];

/// Convert to a [`U64x4`] array.
// TODO(tarcieri): implement all algorithms in terms of `U256`?
#[cfg(target_pointer_width = "32")]
pub(crate) const fn u256_to_u64x4(u256: U256) -> U64x4 {
    let limbs = u256.to_words();

    [
        (limbs[0] as u64) | ((limbs[1] as u64) << 32),
        (limbs[2] as u64) | ((limbs[3] as u64) << 32),
        (limbs[4] as u64) | ((limbs[5] as u64) << 32),
        (limbs[6] as u64) | ((limbs[7] as u64) << 32),
    ]
}

/// Convert to a [`U64x4`] array.
// TODO(tarcieri): implement all algorithms in terms of `U256`?
#[cfg(target_pointer_width = "64")]
pub(crate) const fn u256_to_u64x4(u256: U256) -> U64x4 {
    u256.to_words()
}

/// Convert from a [`U64x4`] array.
#[cfg(target_pointer_width = "32")]
pub(crate) const fn u64x4_to_u256(limbs: U64x4) -> U256 {
    U256::from_words([
        (limbs[0] & 0xFFFFFFFF) as u32,
        (limbs[0] >> 32) as u32,
        (limbs[1] & 0xFFFFFFFF) as u32,
        (limbs[1] >> 32) as u32,
        (limbs[2] & 0xFFFFFFFF) as u32,
        (limbs[2] >> 32) as u32,
        (limbs[3] & 0xFFFFFFFF) as u32,
        (limbs[3] >> 32) as u32,
    ])
}

/// Convert from a [`U64x4`] array.
// TODO(tarcieri): implement all algorithms in terms of `U256`?
#[cfg(target_pointer_width = "64")]
pub(crate) const fn u64x4_to_u256(limbs: U64x4) -> U256 {
    U256::from_words(limbs)
}
