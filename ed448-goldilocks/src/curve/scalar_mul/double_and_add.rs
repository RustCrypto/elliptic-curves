use crate::curve::twedwards::extended::ExtendedPoint;
use subtle::{Choice, ConditionallySelectable};

/// Traditional double and add algorithm
pub(crate) fn double_and_add(point: &ExtendedPoint, s_bits: [bool; 448]) -> ExtendedPoint {
    let mut result = ExtendedPoint::IDENTITY;

    // NB, we reverse here, so we are going from MSB to LSB
    // XXX: Would be great if subtle had a From<u32> for Choice. But maybe that is not it's purpose?
    for bit in s_bits.into_iter().rev() {
        result = result.double();
        result.conditional_assign(&(result.add(point)), Choice::from(u8::from(bit)));
    }

    result
}
