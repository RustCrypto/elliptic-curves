//! Basic validity tests for both brainpoolP512 variants.

use bp512::t1::AffinePoint;
use elliptic_curve::sec1::{FromSec1Point, ToSec1Point};

#[test]
fn twisted_generator_is_on_curve() {
    let encoded = AffinePoint::GENERATOR.to_sec1_point(false);
    assert!(bool::from(AffinePoint::from_sec1_point(&encoded).is_some()));
}
