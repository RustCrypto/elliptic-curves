/// Ed448 contexts as used by Ed448ph.
///
/// Contexts are domain separator strings that can be used to isolate uses of
/// the algorithm between different protocols (which is very hard to reliably do
/// otherwise) and between different uses within the same protocol.
///
/// To create a context, call either of the following:
///
/// - [`SigningKey::with_context`](crate::SigningKey::with_context)
/// - [`VerifyingKey::with_context`](crate::VerifyingKey::with_context)
#[derive(Copy, Clone, Debug)]
pub struct Context<'k, 'v, K> {
    pub(crate) key: &'k K,
    pub(crate) value: &'v [u8],
}

impl<'k, 'v, K> Context<'k, 'v, K> {
    /// Maximum length of a context string.
    pub const MAX_LENGTH: usize = 255;

    /// Borrow the key
    pub fn key(&self) -> &'k K {
        self.key
    }

    /// Borrow the value
    pub fn value(&self) -> &'v [u8] {
        self.value
    }
}
