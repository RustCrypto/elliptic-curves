#![allow(non_snake_case)]

use super::window::wnaf::LookupTable;
use crate::curve::twedwards::{extended::ExtendedPoint, extensible::ExtensiblePoint};
use crate::field::Scalar;
use subtle::{Choice, ConditionallyNegatable};

pub fn variable_base(point: &ExtendedPoint, s: &Scalar) -> ExtendedPoint {
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

        result = result.add_projective_niels(&neg_P);
    }

    result.to_extended()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve::scalar_mul::double_and_add;
    use crate::TWISTED_EDWARDS_BASE_POINT;
    use crypto_bigint::U448;

    #[test]
    fn test_scalar_mul() {
        // XXX: In the future use known multiples from Sage in bytes form?
        let twisted_point = TWISTED_EDWARDS_BASE_POINT;
        let scalar = Scalar(U448::from_be_hex(
            "05ca185aee2e1b73def437f63c003777083f83043fe5bf1aab454c66b64629d1de8026c1307f665ead0b70151533427ce128ae786ee372b7"
        ));

        let got = variable_base(&twisted_point, &scalar);

        let got2 = double_and_add(&twisted_point, &scalar);
        assert_eq!(got, got2);

        // Lets see if this is conserved over the isogenies
        let edwards_point = twisted_point.to_untwisted();
        let got_untwisted_point = edwards_point.scalar_mul(&scalar);
        let expected_untwisted_point = got.to_untwisted();
        assert_eq!(got_untwisted_point, expected_untwisted_point);
    }

    #[test]
    fn test_simple_scalar_mul_identities() {
        let x = TWISTED_EDWARDS_BASE_POINT;

        // Test that 1 * P = P
        let exp = variable_base(&x, &Scalar::from(1u8));
        assert!(x == exp);
        // Test that 2 * (P + P) = 4 * P
        let x_ext = x.to_extensible();
        let expected_two_x = x_ext.add_extensible(&x_ext).double();
        let got = variable_base(&x, &Scalar::from(4u8));
        assert!(expected_two_x.to_extended() == got);
    }
}
