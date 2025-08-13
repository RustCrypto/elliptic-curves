/// This module will contain the EC arithmetic for the Twisted Edwards form of Goldilocks.
/// with the following affine equation : -x^2 + y^2 = 1 - 39082x^2y^2
/// This curve will be used as a backend for the Goldilocks and Decaf through the use of isogenies.
/// It will not be exposed in the public API.
pub(crate) mod affine;
pub(crate) mod extended;
pub(crate) mod extensible;
pub(crate) mod projective;

use crate::field::FieldElement;

pub(crate) struct IsogenyMap {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) T: FieldElement,
    pub(crate) Z: FieldElement,
}

impl IsogenyMap {
    // (1.) https://eprint.iacr.org/2014/027.pdf
    pub(crate) fn map(&self, scale: impl FnOnce(FieldElement) -> FieldElement) -> Self {
        // x = 2xy / (y^2 - a*x^2)
        // y = (y^2 + a*x^2) / (2 - y^2 - a*x^2)

        // Derive algorithm for projective form:

        // x = X / Z
        // y = Y / Z
        // xy = T / Z
        // x^2 = X^2 / Z^2
        // y^2 = y^2 / Z^2

        // x = 2xy / (y^2 - a*x^2)
        // x = (2T/Z) / (Y^2/Z^2 + a*X^2/Z^2)
        // x = 2TZ / (Y^2 - a*X^2)

        // y = (y^2 + a*x^2) / (2 - y^2 - a*x^2)
        // y = (Y^2/Z^2 + a*X^2/Z^2) / (2 - Y^2/Z^2 - a*X^2/Z^2)
        // y = (Y^2 + a*X^2) / (2*Z^2 - Y^2 - a*X^2)

        let xx = self.X.square();
        let yy = self.Y.square();
        let axx = scale(xx);
        let yy_plus_axx = yy + axx;

        // Compute x
        let x_numerator = (self.T * self.Z).double();
        let x_denom = yy - axx;

        // Compute y
        let y_numerator = yy_plus_axx;
        let y_denom = self.Z.square().double() - yy_plus_axx;

        let X = x_numerator * y_denom;
        let Y = y_numerator * x_denom;
        let T = x_numerator * y_numerator;
        let Z = x_denom * y_denom;

        Self { X, Y, T, Z }
    }
}
