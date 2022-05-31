//! Field arithmetic macros

// TODO(tarcieri): extract this into the `elliptic-curve` crate when stable

/// Emit impls for a `core::ops` trait for all combinations of reference types,
/// which thunk to the given function.
macro_rules! impl_field_op {
    ($name:tt, $inner:ty, $op:tt, $op_fn:ident, $func:ident) => {
        impl $op for $name {
            type Output = $name;

            #[inline]
            fn $op_fn(self, rhs: $name) -> $name {
                let mut out = <$inner>::default();
                $func(out.as_mut(), self.as_ref(), rhs.as_ref());
                $name(out)
            }
        }

        impl $op<&$name> for $name {
            type Output = $name;

            #[inline]
            fn $op_fn(self, rhs: &$name) -> $name {
                let mut out = <$inner>::default();
                $func(out.as_mut(), self.as_ref(), rhs.as_ref());
                $name(out)
            }
        }

        impl $op<&$name> for &$name {
            type Output = $name;

            #[inline]
            fn $op_fn(self, rhs: &$name) -> $name {
                let mut out = <$inner>::default();
                $func(out.as_mut(), self.as_ref(), rhs.as_ref());
                $name(out)
            }
        }
    };
}
