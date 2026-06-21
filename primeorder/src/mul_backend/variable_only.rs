use super::MulBackend;
use crate::PrimeCurveParams;

/// Simple backend that only supports variable-base scalar multiplication.
pub struct VariableOnly;

impl<C: PrimeCurveParams> MulBackend<C> for VariableOnly {}
