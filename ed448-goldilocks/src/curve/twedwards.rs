/// This module will contain the EC arithmetic for the Twisted Edwards form of Goldilocks.
/// with the following affine equation : -x^2 + y^2 = 1 - 39082x^2y^2
/// This curve will be used as a backend for the Goldilocks, Ristretto and Decaf through the use of isogenies.
/// It will not be exposed in the public API.
pub(crate) mod affine;
pub(crate) mod extended;
pub(crate) mod extensible;
pub(crate) mod projective;
