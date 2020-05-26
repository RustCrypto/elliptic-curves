//! Scalar field arithmetic.

use core::convert::TryInto;
use subtle::{Choice, CtOption};

use crate::{arithmetic::util::sbb, SecretKey};

/// The number of 64-bit limbs used to represent a [`Scalar`].
const LIMBS: usize = 4;

/// Constant representing the modulus
/// n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
const MODULUS: [u64; LIMBS] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/// An element in the finite field modulo n.
// TODO: This currently uses native representation internally, but will probably move to
// Montgomery representation later.
#[derive(Clone, Copy, Debug)]
pub struct Scalar(pub(crate) [u64; LIMBS]);

impl From<u64> for Scalar {
    fn from(k: u64) -> Self {
        Scalar([k, 0, 0, 0])
    }
}

impl Scalar {
    /// Returns the zero scalar.
    pub const fn zero() -> Scalar {
        Scalar([0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Scalar {
        Scalar([1, 0, 0, 0])
    }

    /// Attempts to convert a `SecretKey` (defined in the more generic `elliptic_curve` crate) to a
    /// `Scalar`
    ///
    /// Returns None if the secret's underlying value does not represent a field element.
    pub fn from_secret(s: SecretKey) -> CtOption<Scalar> {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(s.secret_scalar().as_ref());
        // We can't unwrap() this, since it's not guaranteed that s represents a valid field elem
        Self::from_bytes(buf)
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let mut w = [0u64; LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        // If w is in the range [0, n) then w - n will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS[3], borrow);
        let is_some = (borrow as u8) & 1;

        CtOption::new(Scalar(w), Choice::from(is_some))
    }

    /// Returns the SEC-1 encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0; 32];
        ret[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        ret
    }
}

// Tests that a Scalar can be safely converted to a SecretKey and back
#[test]
fn from_ec_secret() {
    let scalar = Scalar::one();
    let secret = SecretKey::from_bytes(scalar.to_bytes()).unwrap();
    let rederived_scalar = Scalar::from_secret(secret).unwrap();
    assert_eq!(scalar.0, rederived_scalar.0);
}
