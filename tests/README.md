# no_std tests

This directory and associated CI configs in `.github` is a workaround for
issues with the `cargo` resolver activating features from dev-dependencies
which cause `std` to get linked in a release target.

It contains small test crates in their own isolated workspace which ensure that
these features are not activated when linking and therefore that the crates
will link in `no_std` environments when consumed as a dependency of another
`no_std`-compatible crate.

Here are upstream issues tracking the problem:

- [#7914: Tracking issue for `-Z features=itarget`](https://github.com/rust-lang/cargo/issues/7914)
- [#7915: Tracking issue for `-Z features=host_dep`](https://github.com/rust-lang/cargo/issues/7915)
- [#7916: Tracking issue for `-Z features=dev_dep`](https://github.com/rust-lang/cargo/issues/7916])
