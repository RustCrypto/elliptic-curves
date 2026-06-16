use super::Backend;
use crate::PrimeCurveParams;

/// Simple backend that only supports variable-base scalar multiplication.
pub struct VariableOnly;

impl<C: PrimeCurveParams> Backend<C> for VariableOnly {}
