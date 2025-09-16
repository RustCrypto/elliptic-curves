//! Error types.

use core::fmt;

/// Error type.
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "field error")
    }
}

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;
