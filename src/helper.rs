use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    AffinePoint, FieldBytes, PublicKey, Scalar,
};
use rand::{thread_rng, RngCore};
use tiny_keccak::{Hasher, Keccak};

/// Calculate witness address from a Affine
pub fn calculate_witness_address(witness: &AffinePoint) -> Scalar {
    let encoded_point = witness.to_encoded_point(true);
    let point_bytes = encoded_point.as_bytes();

    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(point_bytes);
    hasher.finalize(&mut output);

    let mut address = [0u8; 20];
    address.copy_from_slice(&output[12..32]);

    let bytes = FieldBytes::from_slice(&address);
    Scalar::from_repr(*bytes).unwrap()
}

/// Has a Public Key and return a Ethereum address
pub fn get_address(pub_key: &PublicKey) -> Scalar {
    let affine_pub: AffinePoint = pub_key.into();
    calculate_witness_address(&affine_pub)
}

/// Random bytes array
pub fn random_bytes(buf: &mut [u8]) {
    let mut rng = thread_rng();
    rng.fill_bytes(buf);
}
