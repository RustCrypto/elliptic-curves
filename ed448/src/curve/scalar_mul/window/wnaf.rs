use crate::curve::twedwards::extended::ExtendedPoint;
use crate::curve::twedwards::projective::ProjectiveNielsPoint;
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub struct LookupTable([ProjectiveNielsPoint; 8]);

/// Precomputes odd multiples of the point passed in
impl From<&ExtendedPoint> for LookupTable {
    fn from(point: &ExtendedPoint) -> LookupTable {
        let P = point.to_extensible();

        let mut table = [P.to_projective_niels(); 8];

        for i in 1..8 {
            table[i] = P.add_projective_niels(&table[i - 1]).to_projective_niels();
        }

        LookupTable(table)
    }
}

impl LookupTable {
    /// Selects a projective niels point from a lookup table in constant time
    pub fn select(&self, index: u32) -> ProjectiveNielsPoint {
        let mut result = ProjectiveNielsPoint::identity();

        for i in 1..9 {
            let swap = index.ct_eq(&(i as u32));
            result.conditional_assign(&self.0[i - 1], swap);
        }
        result
    }
}

// XXX: Add back tests to ensure that select works correctly

#[test]
fn test_lookup() {
    let p = ExtendedPoint::GENERATOR;
    let points = LookupTable::from(&p);

    let mut expected_point = ExtendedPoint::IDENTITY;
    for i in 0..8 {
        let selected_point = points.select(i);
        assert_eq!(selected_point.to_extended(), expected_point);

        expected_point = expected_point
            .to_extensible()
            .add_extended(&p)
            .to_extended();
    }
}
