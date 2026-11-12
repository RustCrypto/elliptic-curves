//! Check that the field macros don't rely on anything being in scope at the call site,
//! and that they can be invoked for several fields in the same module.

mod fields {
    #![no_implicit_prelude]

    // NIST P-192 base field and scalar field moduli.
    const FIELD_MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffeffffffffffffffff";
    const ORDER_HEX: &str = "ffffffffffffffffffffffff99def836146bc9b1b4d22831";

    ::primefield::monty_field_params! {
        name: FieldParams,
        modulus: FIELD_MODULUS_HEX,
        uint: ::primefield::bigint::U192,
        byte_order: ::primefield::ByteOrder::BigEndian,
        multiplicative_generator: 11,
        doc: "Base field parameters"
    }

    ::primefield::monty_field_element! {
        name: FieldElement,
        params: FieldParams,
        uint: ::primefield::bigint::U192,
        doc: "Base field element"
    }

    ::primefield::monty_field_arithmetic! {
        name: FieldElement,
        params: FieldParams,
        uint: ::primefield::bigint::U192
    }

    ::primefield::monty_field_reduce! {
        name: FieldElement,
        params: FieldParams,
        uint: ::primefield::bigint::U192,
    }

    ::primefield::monty_field_params! {
        name: ScalarParams,
        modulus: ORDER_HEX,
        uint: ::primefield::bigint::U192,
        byte_order: ::primefield::ByteOrder::BigEndian,
        multiplicative_generator: 3,
        doc: "Scalar field parameters"
    }

    ::primefield::monty_field_element! {
        name: Scalar,
        params: ScalarParams,
        uint: ::primefield::bigint::U192,
        doc: "Scalar field element"
    }

    ::primefield::monty_field_arithmetic! {
        name: Scalar,
        params: ScalarParams,
        uint: ::primefield::bigint::U192
    }

    ::primefield::monty_field_reduce! {
        name: Scalar,
        params: ScalarParams,
        uint: ::primefield::bigint::U192,
    }
}

use fields::{FieldElement, Scalar};
use primefield::bigint::U192;

mod field_element_tests {
    use super::{FieldElement, U192};
    primefield::test_primefield!(FieldElement, U192);
}

mod scalar_tests {
    use super::{Scalar, U192};
    primefield::test_primefield!(Scalar, U192);
}
