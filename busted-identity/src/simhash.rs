//! SimHash — locality-sensitive hashing for embedding vectors.
//!
//! Uses 64 random hyperplanes generated from a deterministic xorshift64
//! PRNG to project high-dimensional vectors into 64-bit fingerprints.
//! Similar vectors produce similar fingerprints (measured by Hamming distance).

/// Number of hyperplanes (= number of bits in the fingerprint).
const NUM_PLANES: usize = 64;

/// Deterministic seed for reproducible hyperplane generation.
const SEED: u64 = 0xBEEF_CAFE_DEAD_F00D;

/// Precomputed hyperplanes for SimHash projection.
pub struct SimHasher {
    /// 64 hyperplane vectors, each with `dim` components.
    planes: Vec<Vec<f32>>,
}

impl SimHasher {
    /// Create a SimHasher for vectors of the given dimensionality.
    ///
    /// Generates 64 random hyperplanes using xorshift64 PRNG with a fixed seed.
    pub fn new(dim: usize) -> Self {
        let mut rng_state = SEED;
        let mut planes = Vec::with_capacity(NUM_PLANES);

        for _ in 0..NUM_PLANES {
            let mut plane = Vec::with_capacity(dim);
            for _ in 0..dim {
                rng_state = xorshift64(rng_state);
                // Map u64 to f32 in [-1, 1]
                let val = (rng_state as f64 / u64::MAX as f64) * 2.0 - 1.0;
                plane.push(val as f32);
            }
            planes.push(plane);
        }

        Self { planes }
    }

    /// Compute the 64-bit SimHash fingerprint of a vector.
    pub fn hash(&self, vector: &[f32]) -> u64 {
        let mut fingerprint: u64 = 0;

        for (i, plane) in self.planes.iter().enumerate() {
            let dot: f32 = vector.iter().zip(plane.iter()).map(|(a, b)| a * b).sum();

            if dot >= 0.0 {
                fingerprint |= 1 << i;
            }
        }

        fingerprint
    }

    /// Compute similarity between two SimHash fingerprints.
    ///
    /// Returns a value in [0.0, 1.0] based on Hamming distance.
    /// 1.0 = identical, 0.0 = maximally different.
    pub fn similarity(a: u64, b: u64) -> f32 {
        let hamming = (a ^ b).count_ones();
        1.0 - (hamming as f32 / NUM_PLANES as f32)
    }
}

/// Xorshift64 PRNG — fast, deterministic, good enough for random projections.
fn xorshift64(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hash() {
        let hasher = SimHasher::new(4);
        let vec = [1.0, 2.0, 3.0, 4.0];
        let h1 = hasher.hash(&vec);
        let h2 = hasher.hash(&vec);
        assert_eq!(h1, h2);
    }

    #[test]
    fn identical_vectors_max_similarity() {
        assert_eq!(
            SimHasher::similarity(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            1.0
        );
    }

    #[test]
    fn opposite_fingerprints_zero_similarity() {
        assert_eq!(SimHasher::similarity(0x0, 0xFFFF_FFFF_FFFF_FFFF), 0.0);
    }

    #[test]
    fn similar_vectors_high_similarity() {
        let hasher = SimHasher::new(384);
        let v1: Vec<f32> = (0..384).map(|i| i as f32 * 0.01).collect();
        let v2: Vec<f32> = (0..384).map(|i| i as f32 * 0.01 + 0.001).collect();
        let h1 = hasher.hash(&v1);
        let h2 = hasher.hash(&v2);
        let sim = SimHasher::similarity(h1, h2);
        assert!(
            sim > 0.8,
            "similar vectors should have high similarity, got {sim}"
        );
    }

    #[test]
    fn different_vectors_lower_similarity() {
        let hasher = SimHasher::new(384);
        let v1: Vec<f32> = (0..384).map(|i| i as f32 * 0.01).collect();
        let v2: Vec<f32> = (0..384).map(|i| -(i as f32) * 0.01).collect();
        let h1 = hasher.hash(&v1);
        let h2 = hasher.hash(&v2);
        let sim = SimHasher::similarity(h1, h2);
        assert!(
            sim < 0.5,
            "opposite vectors should have low similarity, got {sim}"
        );
    }

    #[test]
    fn xorshift_deterministic() {
        let s1 = xorshift64(42);
        let s2 = xorshift64(42);
        assert_eq!(s1, s2);
        assert_ne!(s1, 42); // Should be different from input
    }
}
