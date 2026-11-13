//! Check that the exported macros don't rely on anything being in scope at the call site.

mod scalar {
    #![no_implicit_prelude]

    // NIST P-192 scalar field modulus.
    const ORDER_HEX: &str = "ffffffffffffffffffffffff99def836146bc9b1b4d22831";

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

    ::wnaf::impl_wnaf_size_for_scalar!(Scalar);
}

use primefield::ff::PrimeField;
use wnaf::{WnafSize, array::typenum::Unsigned};

#[test]
fn wnaf_storage_size() {
    assert_eq!(
        <scalar::Scalar as WnafSize>::StorageSize::USIZE,
        scalar::Scalar::NUM_BITS as usize + 1
    );
}
