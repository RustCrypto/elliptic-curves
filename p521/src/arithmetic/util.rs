//! Utility functions.

/// Convert an 17-element array of `u32` into a 9-element array of `u64`,
/// assuming integer arrays are in little-endian order.
#[cfg(target_pointer_width = "32")]
pub(crate) const fn u32x17_to_u64x9(w: &[u32; 17]) -> [u64; 9] {
    let mut ret = [0u64; 9];
    let mut i = 0;

    while i < 8 {
        ret[i] = (w[i * 2] as u64) | ((w[(i * 2) + 1] as u64) << 32);
        i += 1;
    }

    ret[i] = w[i * 2] as u64;
    ret
}

/// Convert a 9-element array of `u64` into an 17-element array of `u32`,
/// assuming integers are in little-endian order.
#[cfg(target_pointer_width = "32")]
pub(crate) const fn u64x9_to_u32x17(w: &[u64; 9]) -> [u32; 17] {
    let mut ret = [0u32; 17];
    let mut i = 0;

    while i < 8 {
        ret[i * 2] = (w[i] & 0xFFFFFFFF) as u32;
        ret[(i * 2) + 1] = (w[i] >> 32) as u32;
        i += 1;
    }

    ret[i * 2] = (w[i] & 0xFFFFFFFF) as u32;
    debug_assert!((w[i] >> 32) == 0);

    ret
}
