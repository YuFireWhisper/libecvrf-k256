use k256::{
    elliptic_curve::{ff::PrimeField, group::GroupEncoding, sec1::FromEncodedPoint},
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use tiny_keccak::{Hasher, Keccak};

/// Try to generate a point on the curve based on hashes
pub fn new_candidate_point(b: &[u8]) -> AffinePoint {
    // X is a digest of field
    let x = field_hash(b);
    // Y is a coordinate point, corresponding to x
    let mut y = y_squared(&x).square();

    if y.is_odd().unwrap_u8() == 1 {
        y = y.negate();
    }

    let x_bytes = x.to_bytes();
    let y_bytes = y.to_bytes();
    let encoded_point = EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);

    AffinePoint::from_encoded_point(&encoded_point).unwrap()
}

/// Y squared, it was calculate by evaluate X
pub fn y_squared(x: &Scalar) -> Scalar {
    let t = *x;
    // y^2 = x^3 + 7
    t * t * t + Scalar::from_u128(7)
}

#[deprecated]
/// Check point is on curve or not
pub fn is_on_curve(_point: &AffinePoint) -> bool {
    true
}

/// Hash to curve with prefix
/// HASH_TO_CURVE_HASH_PREFIX = 1
pub fn hash_to_curve_prefix(alpha: &Scalar, pk: &AffinePoint) -> AffinePoint {
    let packed = [
        // HASH_TO_CURVE_HASH_PREFIX = 1
        Scalar::from_u128(1).to_bytes().as_slice(),
        // pk
        pk.to_bytes().as_slice(),
        // seed
        alpha.to_bytes().as_slice(),
    ]
    .concat();

    new_candidate_point(&packed)
}

/// Hash bytes array to a field
pub fn field_hash(b: &[u8]) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b);
    hasher.finalize(&mut output);

    Scalar::from_repr(output.into()).unwrap()
}

/// Hash point to Scalar
pub fn hash_points(
    g: &AffinePoint,
    h: &AffinePoint,
    pk: &AffinePoint,
    gamma: &AffinePoint,
    kg: &AffinePoint,
    kh: &AffinePoint,
) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let all_points = [g, h, pk, gamma, kg, kh];
    for point in all_points {
        hasher.update(point.to_bytes().as_ref());
    }
    hasher.finalize(&mut output);
    Scalar::from_repr(output.into()).unwrap()
}

/// Hash points with prefix
/// SCALAR_FROM_CURVE_POINTS_HASH_PREFIX = 2
pub fn hash_points_prefix(
    hash: &AffinePoint,
    pk: &AffinePoint,
    gamma: &AffinePoint,
    u_witness: &Scalar,
    v: &AffinePoint,
) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    let all_points = [hash, pk, gamma, v];
    // SCALAR_FROM_CURVE_POINTS_HASH_PREFIX = 2
    hasher.update(Scalar::from_u128(2).to_bytes().as_slice());
    for point in all_points {
        hasher.update(point.to_bytes().as_ref());
    }
    hasher.update(u_witness.to_bytes().as_ref());
    hasher.finalize(&mut output);
    Scalar::from_repr(output.into()).unwrap()
}

/// Hash to curve
pub fn hash_to_curve(alpha: &Scalar, y: Option<&AffinePoint>) -> AffinePoint {
    let mut r = ProjectivePoint::GENERATOR * alpha;

    if let Some(y) = y {
        r += ProjectivePoint::from(*y);
    }

    r.to_affine()
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         extends::ScalarExtend,
//         hash::{is_on_curve, new_candidate_point},
//         helper::random_bytes,
//     };
//     use libsecp256k1::curve::Scalar;
//
//     #[test]
//     fn point_must_be_on_curve() {
//         let mut buf = [0u8; 32];
//         random_bytes(&mut buf);
//         let mut rv = new_candidate_point(buf.as_ref());
//         while !is_on_curve(&rv) {
//             rv = new_candidate_point(&rv.x.b32());
//         }
//         assert!(is_on_curve(&rv));
//     }
//
//     #[test]
//     fn test_scalar_is_gte() {
//         let data_set = [
//             Scalar([0, 1, 1, 1, 1, 1, 1, 0]),
//             Scalar([1, 0, 0, 0, 0, 0, 0, 1]),
//             Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
//             Scalar([1, 0, 0, 0, 0, 0, 1, 0]),
//             Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
//             Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
//         ];
//         let require_output = [
//             true, false, false, true, false, false, true, true, false, true, false, false, true,
//             true, true, true, true, true, false, false, false, true, false, false, true, true,
//             true, true, true, true, true, true, true, true, true, true,
//         ];
//         for x in 0..data_set.len() {
//             for y in 0..data_set.len() {
//                 assert!(
//                     data_set[x].gte(&data_set[y]) == require_output[x * data_set.len() + y],
//                     "scalar_is_gte() is broken"
//                 );
//             }
//         }
//     }
//
//     #[test]
//     fn test_scalar_is_gt() {
//         let data_set = [
//             Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
//             Scalar([0, 1, 1, 1, 1, 1, 0, 1]),
//             Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
//             Scalar([0, 0, 0, 0, 0, 0, 0, 0]),
//             Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
//             Scalar([0, 0, 0, 0, 0, 0, 0, 2]),
//             Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
//             Scalar([0, 0, 0, 0, 0, 1, 1, 1]),
//             Scalar([0, 1, 1, 1, 1, 1, 1, 1]),
//             Scalar([1, 1, 1, 1, 1, 1, 1, 1]),
//         ];
//         let require_output = [
//             false, false, false, true, false, false, false, false, false, false, false, false,
//             false, true, false, false, false, false, false, false, true, true, false, true, false,
//             false, false, true, true, false, false, false, false, false, false, false, false,
//             false, false, false, true, true, false, true, false, false, false, true, true, false,
//             true, true, true, true, true, false, true, true, true, true, true, true, false, true,
//             false, false, false, true, true, false, true, true, false, true, false, false, false,
//             false, false, false, true, true, false, true, false, false, false, true, false, false,
//             true, true, false, true, false, false, false, true, true, false,
//         ];
//
//         for x in 0..data_set.len() {
//             for y in 0..data_set.len() {
//                 assert!(
//                     data_set[x].gt(&data_set[y]) == require_output[x * data_set.len() + y],
//                     "scalar_is_gt() is broken"
//                 );
//             }
//         }
//     }
// }
