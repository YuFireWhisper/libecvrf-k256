use crate::{
    error,
    hash::{hash_points, hash_to_curve},
};
use k256::{
    elliptic_curve::{
        rand_core::OsRng,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        subtle::ConditionallyNegatable,
        Field, PrimeField,
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

/// EC-VRF proof
#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
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
    pub fn prove(&self, alpha: &[u8]) -> Result<ECVRFProof, error::Error> {
        let alpha = Self::generate_alpha(alpha);

        let pub_affine: AffinePoint = self.public_key.into();
        let secret_key: Scalar = *self.secret_key.to_nonzero_scalar();

        // Hash to a point on curve
        let h = hash_to_curve(&alpha, Some(&pub_affine));

        // gamma = H * secret_key
        let gamma = h * secret_key;

        // k = random()
        // We need to make sure that k < GROUP_ORDER
        let k = Scalar::random(&mut OsRng);

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
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(gamma.to_encoded_point(true).as_bytes());
        hasher.finalize(&mut output);
        let bytes = FieldBytes::from_slice(&output);
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
    pub fn verify(alpha: &[u8], vrf_proof: &ECVRFProof, public_key: &[u8]) -> bool {
        let alpha = Self::generate_alpha(alpha);
        let pub_encoded = EncodedPoint::from_bytes(public_key).unwrap();
        let pub_point = ProjectivePoint::from_encoded_point(&pub_encoded).unwrap();
        let u = pub_point * vrf_proof.c + ProjectivePoint::GENERATOR * vrf_proof.s;

        let h = hash_to_curve(&alpha, Some(&pub_point.to_affine()));

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

    fn generate_alpha(alpha: &[u8]) -> Scalar {
        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(alpha);
        hasher.finalize(&mut output);

        let bytes = FieldBytes::from_slice(&output);
        Scalar::from_repr(*bytes).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use k256::{
        elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
        PublicKey, SecretKey,
    };

    use crate::ECVRF;

    const TEST_ALPHA: &[u8] = b"test alphaddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn success_proof_and_verify() {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = PublicKey::from_secret_scalar(&secret_key.to_nonzero_scalar());

        let ecvrf = ECVRF::new(secret_key);
        let proof = ecvrf.prove(TEST_ALPHA).unwrap();
        assert_eq!(proof.pk, public_key);

        let result = ECVRF::verify(
            TEST_ALPHA,
            &proof,
            public_key.to_encoded_point(true).as_bytes(),
        );
        assert!(result);
    }
}
