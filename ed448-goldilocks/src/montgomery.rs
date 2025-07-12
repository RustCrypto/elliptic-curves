// The original file was a part of curve25519-dalek.
// Copyright (c) 2016-2019 Isis Lovecruft, Henry de Valence
// Copyright (c) 2020 Kevaundray Wedderburn
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>
// - Kevaundray Wedderburn <kevtheappdev@gmail.com>

mod extended;
mod ops;
mod point;
mod scalar;

pub use extended::{ExtendedMontgomeryPoint, ExtendedProjectiveMontgomeryPoint};
pub use point::{MontgomeryPoint, ProjectiveMontgomeryPoint};
pub use scalar::{MontgomeryScalar, MontgomeryScalarBytes, WideMontgomeryScalarBytes};

/// The default hash to curve domain separation tag
const DEFAULT_HASH_TO_CURVE_SUITE: &[u8] = b"curve448_XOF:SHAKE256_ELL2_RO_";
/// The default encode to curve domain separation tag
const DEFAULT_ENCODE_TO_CURVE_SUITE: &[u8] = b"curve448_XOF:SHAKE256_ELL2_NU_";
