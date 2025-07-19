# [RustCrypto]: Ed448-Goldilocks Elliptic Curve

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.

## About

This crate provides a pure Rust implementation of Curve448, Edwards, and Decaf.
It is intended to be portable, fast, and safe.

## Usage

```rust
use ed448_goldilocks::{Ed448, EdwardsPoint, CompressedEdwardsY, EdwardsScalar, sha3::Shake256};
use elliptic_curve::Field;
use hash2curve::{ExpandMsgXof, GroupDigest};
use rand_core::OsRng;

let secret_key = EdwardsScalar::TWO;
let public_key = EdwardsPoint::GENERATOR * &secret_key;

assert_eq!(public_key, EdwardsPoint::GENERATOR + EdwardsPoint::GENERATOR);

let secret_key = EdwardsScalar::try_from_rng(&mut OsRng).unwrap();
let public_key = EdwardsPoint::GENERATOR * &secret_key;
let compressed_public_key = public_key.compress();

assert_eq!(compressed_public_key.to_bytes().len(), 57);

let hashed_scalar = Ed448::hash_to_scalar::<ExpandMsgXof<Shake256>>(&[b"test"], &[b"edwards448_XOF:SHAKE256_ELL2_RO_"]).unwrap();
let input = hex_literal::hex!("c8c6c8f584e0c25efdb6af5ad234583c56dedd7c33e0c893468e96740fa0cf7f1a560667da40b7bde340a39252e89262fcf707d1180fd43400");
let expected_scalar = EdwardsScalar::from_canonical_bytes(&input.into()).unwrap();
assert_eq!(hashed_scalar, expected_scalar);

let hashed_point = Ed448::hash_from_bytes::<ExpandMsgXof<Shake256>>(&[b"test"], &[b"edwards448_XOF:SHAKE256_ELL2_RO_"]).unwrap();
let expected = hex_literal::hex!("d15c4427b5c5611a53593c2be611fd3635b90272d331c7e6721ad3735e95dd8b9821f8e4e27501ce01aa3c913114052dce2e91e8ca050f4980");
let expected_point = CompressedEdwardsY(expected).decompress().unwrap();
assert_eq!(hashed_point, expected_point);

let hashed_point = EdwardsPoint::hash_with_defaults(b"test");
assert_eq!(hashed_point, expected_point);
```

## Field Choice

The field size is a Solinas trinomial prime 2^448 - 2^224 -1. This prime is called the Goldilocks prime.

## Curves

This repository implements three curves explicitly and another curve implicitly.

The three explicitly implemented curves are:

- Ed448-Goldilocks

- Curve448

- Twisted-Goldilocks


## Ed448-Goldilocks Curve

- The goldilocks curve is an Edwards curve with affine equation x^2 + y^2 = 1 - 39081x^2y^2 .
- This curve was defined by Mike Hamburg in <https://eprint.iacr.org/2015/625.pdf>. 
- The cofactor of this curve over the goldilocks prime is 4.

## Twisted-Goldilocks Curve

- The twisted goldilocks curve is a Twisted Edwards curve with affine equation y^2 - x^2 = 1 - 39082x^2y^2 .
- This curve is also defined in <https://eprint.iacr.org/2015/625.pdf>.
- The cofactor of this curve over the goldilocks prime is 4.

### Isogeny

- This curve is 2-isogenous to Ed448-Goldilocks. Details of the isogeny can be found here: <https://www.shiftleft.org/papers/isogeny/isogeny.pdf>.

## Curve448

This curve is 2-isogenous to Ed448-Goldilocks. Details of Curve448 can be found here: <https://tools.ietf.org/html/rfc7748>.

The main usage of this curve is for X448.

N.B. In that document there is an Edwards curve that is birationally equivalent to Curve448, with a large `d` value. This curve is not implemented and to my knowledge, has no utility.

## Strategy

The main strategy for group arithmetic on Ed448-Goldilocks is to perform the 2-isogeny to map the point to the Twisted-Goldilocks curve, then use the faster Twisted Edwards formulas to perform scalar multiplication. Computing the 2-isogeny then the dual isogeny will pick up a factor of 4 once we map the point back to the Ed448-Goldilocks curve, so the scalar must be adjusted by a factor of 4. Adjusting the scalar is dependent on the point and the scalar. More details can be found in the 2-isogenous paper.

# Decaf

The Decaf strategy [link paper] is used to build a group of prime order from the Twisted Goldilocks curve. The Twisted Goldilocks curve is used as it has faster formulas. We can also use Curve448 or Ed448-Goldilocks. Decaf takes advantage of an isogeny with a Jacobi Quartic curve which is not explicitly defined. Details of this can be found here: <https://www.shiftleft.org/papers/decaf/decaf.pdf>. However, to my knowledge there is no documentation for the Decaf protocol implemented in this repository, which is a tweaked version of the original decaf protocol linked in the paper.

## Completed Point vs Extensible Point

Deviating from Curve25519-Dalek, this library will implement Extensible points instead of Completed Points. Due to the following observation:

- There is a cost of 3/4 Field multiplications to switch from the CompletedPoint. So if we were to perform repeated doubling, this would add an extra cost for each doubling in projective form. More details on the ExtensiblePoint can be found here [3.2]: <https://www.shiftleft.org/papers/fff/fff.pdf>

## Credits

The library design was taken from Dalek's design of Curve25519. The code for Montgomery curve arithmetic was also taken from Dalek's library.

The golang implementation of Ed448 and libdecaf were used as references.

Special thanks to Mike Hamburg for answering all the questions asked regarding Decaf and goldilocks.

This library adds [hash_to_curve](https://datatracker.ietf.org/doc/rfc9380/) and serialization of structs.

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/ed448-goldilocks?logo=rust
[crate-link]: https://crates.io/crates/ed448-goldilocks
[docs-image]: https://docs.rs/ed448-goldilocks/badge.svg
[docs-link]: https://docs.rs/ed448-goldilocks/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/ed448-goldilocks.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/ed448-goldilocks.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto
