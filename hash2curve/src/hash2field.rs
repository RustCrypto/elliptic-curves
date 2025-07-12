//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;

use core::num::NonZeroU16;

use digest::crypto_common::{KeySizeUser, KeyInit};
pub use expand_msg::{xmd::*, xof::*, *};

use elliptic_curve::array::{
    Array,
    typenum::Unsigned,
};
use elliptic_curve::{Error, Result};

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
pub fn hash_to_field<E, K, T>(data: &[&[u8]], domain: &[&[u8]], out: &mut [T]) -> Result<()>
where
    E: ExpandMsg<K>,
    T: KeyInit + Default,
{
    let len_in_bytes = T::KeySize::USIZE
        .checked_mul(out.len())
        .and_then(|len| len.try_into().ok())
        .and_then(NonZeroU16::new)
        .ok_or(Error)?;
    let mut tmp = Array::<u8, <T as KeySizeUser>::KeySize>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    for o in out.iter_mut() {
        expander.fill_bytes(&mut tmp);
        *o = T::new(&tmp);
    }
    Ok(())
}
