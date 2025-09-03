//! Traits for hashing to field elements.
//!
//! <https://www.rfc-editor.org/rfc/rfc9380.html>

mod expand_msg;

use core::num::NonZeroU16;

pub use expand_msg::{xmd::*, xof::*, *};

use elliptic_curve::{
    array::{Array, ArraySize, typenum::NonZero},
    ops::Reduce,
};

/// Convert an arbitrary byte sequence into a field element.
///
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-hash_to_field-implementatio>
///
/// For the `expand_message` call, `len_in_bytes = L * N`.
///
/// # Errors
///
/// Returns an error if the [`ExpandMsg`] implementation fails.
#[doc(hidden)]
pub fn hash_to_field<const N: usize, E, K, T, L>(
    data: &[&[u8]],
    domain: &[&[u8]],
) -> Result<[T; N], E::Error>
where
    E: ExpandMsg<K>,
    T: Reduce<Array<u8, L>> + Default,
    L: ArraySize + NonZero,
{
    // Completely degenerate case; `N` and `L` would need to be extremely large.
    let len_in_bytes = const {
        assert!(
            L::USIZE.saturating_mul(N) <= u16::MAX as usize,
            "The product of `L` and `N` must not exceed `u16::MAX`."
        );
        NonZeroU16::new(L::U16 * N as u16).expect("N is greater than 0")
    };
    let mut tmp = Array::<u8, L>::default();
    let mut expander = E::expand_message(data, domain, len_in_bytes)?;
    Ok(core::array::from_fn(|_| {
        expander
            .fill_bytes(&mut tmp)
            .expect("never exceeds `len_in_bytes`");
        T::reduce(&tmp)
    }))
}
