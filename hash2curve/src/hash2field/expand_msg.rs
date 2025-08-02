//! `expand_message` interface `for hash_to_field`.

pub(super) mod xmd;
pub(super) mod xof;

use core::num::NonZero;

use digest::{
    Digest, ExtendableOutput, Update, XofReader,
    array::{Array, ArraySize},
    consts::{True, U256},
    typenum::IsLess,
};

/// Salt when the DST is too long
const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";
/// Maximum domain separation tag length
const MAX_DST_LEN: usize = 255;

/// Trait for types implementing expand_message interface for `hash_to_field`.
///
/// `K` is the target security level in bytes:
/// <https://www.rfc-editor.org/rfc/rfc9380.html#section-8.9-2.2>
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-target-security-levels>
///
/// # Errors
/// See implementors of [`ExpandMsg`] for errors.
pub trait ExpandMsg<K> {
    /// Type holding data for the [`Expander`].
    type Expander<'dst>: Expander + Sized;
    /// Error returned by [`ExpandMsg::expand_message`].
    type Error: core::error::Error;

    /// Expands `msg` to the required number of bytes.
    ///
    /// Returns an expander that can be used to call `read` until enough
    /// bytes have been consumed
    fn expand_message<'dst>(
        msg: &[&[u8]],
        dst: &'dst [&[u8]],
        len_in_bytes: NonZero<u16>,
    ) -> Result<Self::Expander<'dst>, Self::Error>;
}

/// Expander that, call `read` until enough bytes have been consumed.
pub trait Expander {
    /// Fill the array with the expanded bytes
    fn fill_bytes(&mut self, okm: &mut [u8]);
}

/// The domain separation tag
///
/// Implements [section 5.3.3 of RFC9380][dst].
///
/// [dst]: https://www.rfc-editor.org/rfc/rfc9380.html#name-using-dsts-longer-than-255-
#[derive(Debug)]
pub(crate) enum Domain<'a, L: ArraySize> {
    /// > 255
    Hashed(Array<u8, L>),
    /// <= 255
    Array(&'a [&'a [u8]]),
}

impl<'a, L: ArraySize + IsLess<U256, Output = True>> Domain<'a, L> {
    pub fn xof<X>(dst: &'a [&'a [u8]]) -> Result<Self, DstError>
    where
        X: Default + ExtendableOutput + Update,
    {
        // https://www.rfc-editor.org/rfc/rfc9380.html#section-3.1-4.2
        if dst.iter().map(|slice| slice.len()).sum::<usize>() == 0 {
            Err(DstError::Empty)
        } else if dst.iter().map(|slice| slice.len()).sum::<usize>() > MAX_DST_LEN {
            if L::USIZE > u8::MAX.into() {
                return Err(DstError::XofSecurityLevel);
            }
            let mut data = Array::<u8, L>::default();
            let mut hash = X::default();
            hash.update(OVERSIZE_DST_SALT);

            for slice in dst {
                hash.update(slice);
            }

            hash.finalize_xof().read(&mut data);

            Ok(Self::Hashed(data))
        } else {
            Ok(Self::Array(dst))
        }
    }

    pub fn xmd<X>(dst: &'a [&'a [u8]]) -> Result<Self, DstError>
    where
        X: Digest<OutputSize = L>,
    {
        // https://www.rfc-editor.org/rfc/rfc9380.html#section-3.1-4.2
        if dst.iter().map(|slice| slice.len()).sum::<usize>() == 0 {
            Err(DstError::Empty)
        } else if dst.iter().map(|slice| slice.len()).sum::<usize>() > MAX_DST_LEN {
            if L::USIZE > u8::MAX.into() {
                return Err(DstError::XmdHash);
            }
            Ok(Self::Hashed({
                let mut hash = X::new();
                hash.update(OVERSIZE_DST_SALT);

                for slice in dst {
                    hash.update(slice);
                }

                hash.finalize()
            }))
        } else {
            Ok(Self::Array(dst))
        }
    }

    pub fn update_hash<HashT: Update>(&self, hash: &mut HashT) {
        match self {
            Self::Hashed(d) => hash.update(d),
            Self::Array(d) => {
                for d in d.iter() {
                    hash.update(d)
                }
            }
        }
    }

    pub fn len(&self) -> u8 {
        match self {
            // Can't overflow because it's checked on creation.
            Self::Hashed(_) => L::U8,
            // Can't overflow because it's checked on creation.
            Self::Array(d) => {
                u8::try_from(d.iter().map(|d| d.len()).sum::<usize>()).expect("length overflow")
            }
        }
    }

    #[cfg(test)]
    pub fn assert(&self, bytes: &[u8]) {
        let data = match self {
            Domain::Hashed(d) => d.to_vec(),
            Domain::Array(d) => d.iter().copied().flatten().copied().collect(),
        };
        assert_eq!(data, bytes);
    }

    #[cfg(test)]
    pub fn assert_dst(&self, bytes: &[u8]) {
        let data = match self {
            Domain::Hashed(d) => d.to_vec(),
            Domain::Array(d) => d.iter().copied().flatten().copied().collect(),
        };
        assert_eq!(data, &bytes[..bytes.len() - 1]);
        assert_eq!(self.len(), bytes[bytes.len() - 1]);
    }
}

/// Error when an empty domain separation tag is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstError {
    /// Empty domain separation tag.
    Empty,
    /// The domain separation tag is too long and needs to be hashed, but the hash function
    /// selected has an output size too large (greater than `255`).
    XmdHash,
    /// The domain separation tag is too long and needs to be hashed, but the chosen `K` (target
    /// security level in bytes) is too large (greater than `127`),
    XofSecurityLevel,
}

impl core::fmt::Display for DstError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DstError::Empty => write!(f, "Empty domain separation tag"),
            DstError::XmdHash => write!(
                f,
                "XMD hash function output size is too large to hash the DST"
            ),
            DstError::XofSecurityLevel => {
                write!(f, "XOF target security level in bytes is too large ")
            }
        }
    }
}

impl core::error::Error for DstError {}
