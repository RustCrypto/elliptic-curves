//! Error type

use core::fmt::{self, Display};

/// Elliptic curve errors
#[derive(Copy, Clone, Debug)]
pub struct Error;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("crypto error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
