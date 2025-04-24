extern crate alloc;
use crate::{
    error,
    hash::{hash_points, hash_to_curve},
};
use alloc::string::String;
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        subtle::ConditionallyNegatable,
        zeroize::Zeroize,
        Field, PrimeField,
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use rand::thread_rng;
use tiny_keccak::{Hasher, Keccak};

/// Max retries for randomize scalar or repeat hash
pub const MAX_RETRIES: u32 = 100;

/// Size of secret key
pub const SECRET_KEY_SIZE: usize = 32;

/// Zeroable trait
pub trait Zeroable {
    /// Zeroize self
    fn zeroize(&mut self);
    /// Check self is zero or not
    fn is_zero(&self) -> bool;
}

#[derive(Debug, Eq, PartialEq)]
/// Key pair
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    pub secret_key: SecretKey,
}

#[derive(Debug, Eq, PartialEq)]
/// Raw key pair
pub struct RawKeyPair {
    /// Raw public key
    pub public_key: EncodedPoint,
    /// Raw secret key
    pub secret_key: FieldBytes,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    /// Generate a new key pair
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let secret_key = SecretKey::random(&mut rng);
        let public_key = PublicKey::from_secret_scalar(&secret_key.to_nonzero_scalar());
        KeyPair {
            public_key,
            secret_key,
        }
    }
}

impl Zeroable for RawKeyPair {
    fn zeroize(&mut self) {
        self.public_key.zeroize();
        self.secret_key.zeroize();
    }

    fn is_zero(&self) -> bool {
        self.public_key == EncodedPoint::identity() && self.secret_key.iter().all(|&b| b == 0)
    }
}

impl From<SecretKey> for KeyPair {
    fn from(value: SecretKey) -> Self {
        KeyPair {
            public_key: PublicKey::from_secret_scalar(&value.to_nonzero_scalar()),
            secret_key: value,
        }
    }
}

impl From<&[u8; SECRET_KEY_SIZE]> for KeyPair {
    fn from(value: &[u8; SECRET_KEY_SIZE]) -> Self {
        let secret_instance = SecretKey::from_slice(value).expect("Can not parse secret key");
        KeyPair {
            public_key: PublicKey::from_secret_scalar(&secret_instance.to_nonzero_scalar()),
            secret_key: secret_instance,
        }
    }
}

impl From<String> for KeyPair {
    fn from(value: String) -> Self {
        let mut secret_key = [0u8; SECRET_KEY_SIZE];
        hex::decode_to_slice(value.trim(), &mut secret_key)
            .expect("Unable to convert secret key to [u8; SECRET_KEY_SIZE]");
        Self::from(&secret_key)
    }
}

impl From<&KeyPair> for RawKeyPair {
    fn from(value: &KeyPair) -> Self {
        RawKeyPair {
            public_key: value.public_key.to_encoded_point(true),
            secret_key: value.secret_key.to_bytes(),
        }
    }
}

impl From<&[u8; SECRET_KEY_SIZE]> for RawKeyPair {
    fn from(value: &[u8; SECRET_KEY_SIZE]) -> Self {
        let field_bytes = FieldBytes::from_slice(value);
        let secret_instance = SecretKey::from_bytes(field_bytes).expect("Can not parse secret key");
        let public_key = PublicKey::from_secret_scalar(&secret_instance.to_nonzero_scalar())
            .to_encoded_point(true);
        RawKeyPair {
            public_key,
            secret_key: *field_bytes,
        }
    }
}

/// EC-VRF proof
#[derive(Clone, Copy, Debug)]
pub struct ECVRFProof {
    /// gamma
    pub gamma: AffinePoint,
    /// c
    pub c: Scalar,
    /// s
    pub s: Scalar,
    /// y is the result
    pub y: Scalar,
    /// Public key
    pub pk: PublicKey,
}

/// EC-VRF contract proof that compatible and verifiable with Solidity contract
#[derive(Clone, Copy, Debug)]
pub struct ECVRFContractProof {
    /// Public key
    pub pk: PublicKey,
    /// gamma
    pub gamma: AffinePoint,
    /// c
    pub c: Scalar,
    /// s
    pub s: Scalar,
    /// Result y
    pub y: Scalar,
    /// Seed alpha
    pub alpha: Scalar,
    /// Witness address
    pub witness_address: Scalar,
    /// Witness gamma
    pub witness_gamma: AffinePoint,
    /// Witness hash
    pub witness_hash: AffinePoint,
    /// Inverse z, easier to verify in Solidity
    pub inverse_z: Scalar,
}

/// ECVRF
pub struct ECVRF {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl ECVRF {
    /// Create new instance of ECVRF from a secret key
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_scalar(&secret_key.to_nonzero_scalar());
        ECVRF {
            secret_key,
            public_key,
        }
    }

    /// Ordinary prover
    pub fn prove(&self, alpha: &Scalar) -> Result<ECVRFProof, error::Error> {
        let pub_affine: AffinePoint = self.public_key.into();
        let secret_key: Scalar = *self.secret_key.to_nonzero_scalar();

        // Hash to a point on curve
        let h = hash_to_curve(alpha, Some(&pub_affine));

        // gamma = H * secret_key
        let gamma = h * secret_key;

        // k = random()
        // We need to make sure that k < GROUP_ORDER
        let k = Scalar::random(thread_rng());

        // Calculate k * G <=> u
        let kg = ProjectivePoint::GENERATOR * k;

        // Calculate k * H <=> v
        let kh = h * k;

        // c = ECVRF_hash_points(G, H, public_key, gamma, k * G, k * H)
        let c = hash_points(
            &AffinePoint::GENERATOR,
            &h,
            &pub_affine,
            &gamma.to_affine(),
            &kg.to_affine(),
            &kh.to_affine(),
        );

        // s = (k - c * secret_key) mod p
        let mut neg_c = c;
        neg_c.conditional_negate(1.into());
        let s = k + neg_c * secret_key;

        // y = keccak256(gama.encode())
        let bytes = gamma.to_encoded_point(true).to_bytes().to_vec();
        let bytes = FieldBytes::from_slice(&bytes);
        let y = Scalar::from_repr(*bytes).unwrap();

        Ok(ECVRFProof {
            gamma: gamma.to_affine(),
            c,
            s,
            y,
            pk: self.public_key,
        })
    }

    /// Verify proof
    pub fn verify(alpha: &Scalar, vrf_proof: &ECVRFProof, public_key: &[u8]) -> bool {
        let pub_encoded = EncodedPoint::from_bytes(public_key).unwrap();
        let pub_point = ProjectivePoint::from_encoded_point(&pub_encoded).unwrap();
        let u = pub_point * vrf_proof.c + ProjectivePoint::GENERATOR * vrf_proof.s;

        let h = hash_to_curve(alpha, Some(&pub_point.to_affine()));

        // Gamma witness: c * gamma
        let witness_gamma = ProjectivePoint::from(vrf_proof.gamma) * vrf_proof.c;

        // Hash witness: s * H
        let witness_hash = ProjectivePoint::from(h) * vrf_proof.s;

        // V = c * gamma + s * H
        let v = witness_gamma + witness_hash;

        // c_prime = ECVRF_hash_points(G, H, pk, gamma, U, V)
        let computed_c = hash_points(
            &AffinePoint::GENERATOR,
            &h,
            &pub_point.to_affine(),
            &vrf_proof.gamma,
            &u.to_affine(),
            &v.to_affine(),
        );

        // y = keccak256(gamma.encode())
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(vrf_proof.gamma.to_encoded_point(true).as_bytes());
        hasher.finalize(&mut output);

        let bytes = FieldBytes::from_slice(&output);
        let computed_y = Scalar::from_repr(*bytes).unwrap();

        computed_c == vrf_proof.c && computed_y == vrf_proof.y
    }
}
