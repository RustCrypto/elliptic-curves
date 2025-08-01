#![allow(non_snake_case)]

use super::window::wnaf::LookupTable;
use crate::Scalar;
use crate::curve::twedwards::{extended::ExtendedPoint, extensible::ExtensiblePoint};
use crate::field::CurveWithScalar;
use subtle::{Choice, ConditionallyNegatable};

pub fn variable_base<C: CurveWithScalar>(point: &ExtendedPoint, s: &Scalar<C>) -> ExtensiblePoint {
    let mut result = ExtensiblePoint::IDENTITY;

    // Recode Scalar
    let scalar = s.to_radix_16();

    let lookup = LookupTable::from(point);

    for i in (0..113).rev() {
        result = result.double();
        result = result.double();
        result = result.double();
        result = result.double();

        // The mask is the top bit, will be 1 for negative numbers, 0 for positive numbers
        let mask = scalar[i] >> 7;
        let sign = mask & 0x1;
        // Use the mask to get the absolute value of scalar
        let abs_value = ((scalar[i] + mask) ^ mask) as u32;

        let mut neg_P = lookup.select(abs_value);
        neg_P.conditional_negate(Choice::from((sign) as u8));

        result = result.to_extended().add_projective_niels(&neg_P);
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::EdwardsScalar;
    use crate::TWISTED_EDWARDS_BASE_POINT;
    use elliptic_curve::bigint::U448;
    use subtle::ConditionallySelectable;

    #[test]
    fn test_scalar_mul() {
        /// Traditional double and add algorithm
        fn double_and_add(point: &ExtendedPoint, s_bits: [bool; 448]) -> ExtensiblePoint {
            let mut result = ExtensiblePoint::IDENTITY;

            // NB, we reverse here, so we are going from MSB to LSB
            // XXX: Would be great if subtle had a From<u32> for Choice. But maybe that is not it's purpose?
            for bit in s_bits.into_iter().rev() {
                result = result.double();
                result.conditional_assign(
                    &result.to_extended().add_extended(point),
                    Choice::from(u8::from(bit)),
                );
            }

            result
        }

        // XXX: In the future use known multiples from Sage in bytes form?
        let twisted_point = TWISTED_EDWARDS_BASE_POINT;
        let scalar = EdwardsScalar::new(U448::from_be_hex(
            "05ca185aee2e1b73def437f63c003777083f83043fe5bf1aab454c66b64629d1de8026c1307f665ead0b70151533427ce128ae786ee372b7",
        ));

        let got = variable_base(&twisted_point, &scalar);

        let got2 = double_and_add(&twisted_point, scalar.bits());
        assert_eq!(got, got2);

        // Lets see if this is conserved over the isogenies
        let edwards_point = twisted_point.to_extensible().to_untwisted();
        let got_untwisted_point = edwards_point.scalar_mul(&scalar);
        let expected_untwisted_point = got.to_untwisted();
        assert_eq!(got_untwisted_point, expected_untwisted_point);
    }

    #[test]
    fn test_simple_scalar_mul_identities() {
        let x = TWISTED_EDWARDS_BASE_POINT;

        // Test that 1 * P = P
        let exp = variable_base(&x, &EdwardsScalar::from(1u8));
        assert!(x == exp);
        // Test that 2 * (P + P) = 4 * P
        let expected_two_x = x.add_extended(&x).double();
        let got = variable_base(&x, &EdwardsScalar::from(4u8));
        assert!(expected_two_x == got);
    }
}
