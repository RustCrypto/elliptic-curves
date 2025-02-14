mod element;
mod scalar;

pub(crate) use element::*;
pub use scalar::{Scalar, ScalarBytes, WideScalarBytes, MODULUS_LIMBS, ORDER, WIDE_ORDER};

use crate::curve::edwards::EdwardsPoint;
use crate::curve::twedwards::extended::ExtendedPoint as TwExtendedPoint;

use elliptic_curve::bigint::{
    impl_modulus,
    modular::constant_mod::{Residue, ResidueParams},
    U448,
};

impl_modulus!(MODULUS, U448, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
pub(crate) type ResidueType = Residue<MODULUS, { MODULUS::LIMBS }>;

pub const GOLDILOCKS_BASE_POINT: EdwardsPoint = EdwardsPoint {
    X: FieldElement(ResidueType::new(&U448::from_be_hex("4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e"))),
    Y: FieldElement(ResidueType::new(&U448::from_be_hex("693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14"))),
    Z: FieldElement::ONE,
    T: FieldElement(ResidueType::new(&U448::from_be_hex("c75eb58aee221c6ccec39d2d508d91c9c5056a183f8451d260d71667e2356d58f179de90b5b27da1f78fa07d85662d1deb06624e82af95f3"))),
};

pub const TWISTED_EDWARDS_BASE_POINT: TwExtendedPoint = TwExtendedPoint {
    X: FieldElement(ResidueType::new(&U448::from_be_hex("7ffffffffffffffffffffffffffffffffffffffffffffffffffffffe80000000000000000000000000000000000000000000000000000000"))),
    Y: FieldElement(ResidueType::new(&U448::from_be_hex("8508de14f04286d48d06c13078ca240805264370504c74c393d5242c5045271414181844d73f48e5199b0c1e3ab470a1c86079b4dfdd4a64"))),
    Z: FieldElement::ONE,
    T: FieldElement(ResidueType::new(&U448::from_be_hex("6d3669e173c6a450e23d5682a9ffe1ddc2b86da60f794be956382384a319b57519c9854dde98e342140362071833f4e093e3c816dc198105"))),
};
