use crate::curve::twedwards::extended::ExtendedPoint;
use crate::curve::twedwards::extensible::ExtensiblePoint;
use subtle::{Choice, ConditionallySelectable};

/// Traditional double and add algorithm
pub(crate) fn double_and_add(point: &ExtendedPoint, s_bits: [bool; 448]) -> ExtensiblePoint {
    let mut result = ExtensiblePoint::IDENTITY;

    // NB, we reverse here, so we are going from MSB to LSB
    // XXX: Would be great if subtle had a From<u32> for Choice. But maybe that is not it's purpose?
    for bit in s_bits.into_iter().rev() {
        result = result.double();

        let mut p = ExtendedPoint::IDENTITY;
        p.conditional_assign(point, Choice::from(bit as u8));
        result = result.to_extended().add_extended(&p);
    }

    result
}
