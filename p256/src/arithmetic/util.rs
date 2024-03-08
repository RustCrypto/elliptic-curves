#[cfg_attr(target_pointer_width = "32", path = "util/util32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "util/util64.rs")]
mod util_impl;

pub(crate) use util_impl::*;
