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

/// Hash bytes array to a field
pub fn field_hash(b: &[u8]) -> Scalar {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(b);
    hasher.finalize(&mut output);

    Scalar::from_repr(output.into()).unwrap()
}

/// Y squared, it was calculate by evaluate X
pub fn y_squared(x: &Scalar) -> Scalar {
    let t = *x;
    // y^2 = x^3 + 7
    t * t * t + Scalar::from_u128(7)
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
