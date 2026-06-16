use crate::ByteOrder;

/// Extension trait for [`ff::PrimeField`] which enables specifying the endianness in which
/// [`ff::PrimeField::Repr`] is encoded.
// TODO(tarcieri): remove this if/whenever zkcrypto/rfcs#4 lands. See also: zkcrypto/ff#158
pub trait PrimeFieldExt: ff::PrimeField {
    /// Endianness used when encoding [`ff::PrimeField::Repr`].
    const REPR_ENDIANNESS: ByteOrder = ByteOrder::BigEndian;

    /// Encode `self` using a big endian representation.
    fn to_be_repr(&self) -> Self::Repr {
        let mut repr = self.to_repr();

        if Self::REPR_ENDIANNESS == ByteOrder::LittleEndian {
            repr.as_mut().reverse();
        }

        repr
    }

    /// Encode `self` using a little endian representation.
    fn to_le_repr(&self) -> Self::Repr {
        let mut repr = self.to_repr();

        if Self::REPR_ENDIANNESS == ByteOrder::BigEndian {
            repr.as_mut().reverse();
        }

        repr
    }
}
