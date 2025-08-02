//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;

use core::num::NonZeroU16;

pub use expand_msg::{xmd::*, xof::*, *};

use digest::array::{
    Array, ArraySize,
    typenum::{NonZero, Unsigned},
};

/// The trait for helping to convert to a field element.
pub trait FromOkm {
    /// The number of bytes needed to convert to a field element.
    type Length: ArraySize + NonZero;

    /// Convert a byte sequence into a field element.
    fn from_okm(data: &Array<u8, Self::Length>) -> Self;
}

/// Convert an arbitrary byte sequence into a field element.
///
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-hash_to_field-implementatio>
///
/// # Errors
///
/// Returns an error if the [`ExpandMsg`] implementation fails.
#[doc(hidden)]
pub fn hash_to_field<const N: usize, E, K, T>(
    data: &[&[u8]],
    domain: &[&[u8]],
) -> Result<[T; N], E::Error>
where
    E: ExpandMsg<K>,
    T: FromOkm + Default,
{
    // Completely degenerate case; `N` and `T::Length` would need to be extremely large.
    const { assert!(T::Length::USIZE * N <= u16::MAX as usize) }
    let Some(len_in_bytes) = NonZeroU16::new(T::Length::U16 * N as u16) else {
        // Since `T::Length: NonZero`, only `N = 0` can lead to this case.
        return Ok(core::array::from_fn(|_| T::default()));
    };
    let mut tmp = Array::<u8, <T as FromOkm>::Length>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    Ok(core::array::from_fn(|_| {
        expander.fill_bytes(&mut tmp);
        T::from_okm(&tmp)
    }))
}
