<p align="center">
<img src="resources/bear.png" width = "400">
</p>

ed448-goldilocks-plus 

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![BSD-3 Licensed][license-image]

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.

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
- This curve was defined by Mike Hamburg in https://eprint.iacr.org/2015/625.pdf . 
- The cofactor of this curve over the goldilocks prime is 4.

## Twisted-Goldilocks Curve

- The twisted goldilocks curve is a Twisted Edwards curve with affine equation y^2 - x^2 = 1 - 39082x^2y^2 .
- This curve is also defined in https://eprint.iacr.org/2015/625.pdf .
- The cofactor of this curve over the goldilocks prime is 4.

### Isogeny

- This curve is 2-isogenous to Ed448-Goldilocks. Details of the isogeny can be found here: https://www.shiftleft.org/papers/isogeny/isogeny.pdf

## Curve448

This curve is 2-isogenous to Ed448-Goldilocks. Details of Curve448 can be found here: https://tools.ietf.org/html/rfc7748

The main usage of this curve is for X448.

N.B. In that document there is an Edwards curve that is birationally equivalent to Curve448, with a large `d` value. This curve is not implemented and to my knowledge, has no utility.

## Strategy

The main strategy for group arithmetic on Ed448-Goldilocks is to perform the 2-isogeny to map the point to the Twisted-Goldilocks curve, then use the faster Twisted Edwards formulas to perform scalar multiplication. Computing the 2-isogeny then the dual isogeny will pick up a factor of 4 once we map the point back to the Ed448-Goldilocks curve, so the scalar must be adjusted by a factor of 4. Adjusting the scalar is dependent on the point and the scalar. More details can be found in the 2-isogenous paper.

# Decaf

The Decaf strategy [link paper] is used to build a group of prime order from the Twisted Goldilocks curve. The Twisted Goldilocks curve is used as it has faster formulas. We can also use Curve448 or Ed448-Goldilocks. Decaf takes advantage of an isogeny with a Jacobi Quartic curve which is not explicitly defined. Details of this can be found here: https://www.shiftleft.org/papers/decaf/decaf.pdf However, to my knowledge there is no documentation for the Decaf protocol implemented in this repository, which is a tweaked version of the original decaf protocol linked in the paper.

## Completed Point vs Extensible Point

Deviating from Curve25519-Dalek, this library will implement Extensible points instead of Completed Points. Due to the following observation:

- There is a cost of 3/4 Field multiplications to switch from the CompletedPoint. So if we were to perform repeated doubling, this would add an extra cost for each doubling in projective form. More details on the ExtensiblePoint can be found here [3.2]: https://www.shiftleft.org/papers/fff/fff.pdf

## Credits

The library design was taken from Dalek's design of Curve25519. The code for Montgomery curve arithmetic was also taken from Dalek's library.

The golang implementation of Ed448 and libdecaf were used as references.

Special thanks to Mike Hamburg for answering all the questions asked regarding Decaf and goldilocks.

This library adds [hash_to_curve](https://datatracker.ietf.org/doc/rfc9380/) and serialization of structs.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the BSD-3-Clause
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/ed448-goldilocks-plus.svg
[crate-link]: https://crates.io/crates/ed448-goldilocks-plus
[docs-image]: https://docs.rs/ed448-goldilocks-plus/badge.svg
[docs-link]: https://docs.rs/ed448-goldilocks-plus/
[license-image]: https://img.shields.io/badge/License-BSD%203--Clause-blue.svg