//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;

use core::num::NonZeroU16;

pub use expand_msg::{xmd::*, xof::*, *};

use elliptic_curve::array::{
    Array, ArraySize,
    typenum::{NonZero, Unsigned},
};
use elliptic_curve::{Error, Result};

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
/// - `len_in_bytes > u16::MAX`
/// - See implementors of [`ExpandMsg`] for additional errors:
///   - [`ExpandMsgXmd`]
///   - [`ExpandMsgXof`]
///
/// `len_in_bytes = T::Length * out.len()`
///
/// [`ExpandMsgXmd`]: crate::hash2field::ExpandMsgXmd
/// [`ExpandMsgXof`]: crate::hash2field::ExpandMsgXof
#[doc(hidden)]
pub fn hash_to_field<const N: usize, E, K, T>(data: &[&[u8]], domain: &[&[u8]]) -> Result<[T; N]>
where
    E: ExpandMsg<K>,
    T: FromOkm + Default,
{
    let len_in_bytes = T::Length::USIZE
        .checked_mul(N)
        .and_then(|len| len.try_into().ok())
        .and_then(NonZeroU16::new)
        .ok_or(Error)?;
    let mut tmp = Array::<u8, <T as FromOkm>::Length>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    Ok(core::array::from_fn(|_| {
        expander.fill_bytes(&mut tmp);
        T::from_okm(&tmp)
    }))
}
