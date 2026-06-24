//! Error types.

use core::fmt;

/// Error type.
#[derive(Clone, Copy, Debug)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "field error")
    }
}

impl core::error::Error for Error {}

/// Result type.
pub type Result<T> = core::result::Result<T, Error>;
