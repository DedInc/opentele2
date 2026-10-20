//! A small, dependency-free seeded random number generator.
//!
//! The generator is xoshiro256** implemented here rather than taken from the
//! `rand` family, so a given seed yields the same stream forever, whatever
//! version of an external crate the build happens to resolve.

use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// 2^-53, the spacing of the doubles produced by [`Rng::next_f64`].
const F64_UNIT: f64 = 1.0 / 9_007_199_254_740_992.0;

/// Replaces the one forbidden xoshiro state (all zero words).
const NONZERO_STATE: [u64; 4] = [
    0x9E37_79B9_7F4A_7C15,
    0xBF58_476D_1CE4_E5B9,
    0x94D0_49BB_1331_11EB,
    0x2545_F491_4F6C_DD1D,
];

/// The xoshiro256** generator that drives every random choice of the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rng {
    state: [u64; 4],
}

impl Rng {
    /// Builds a generator whose state is the SHA-256 digest of the UTF-8
    /// `seed`, read as four little-endian 64-bit words.
    #[must_use]
    pub fn from_seed(seed: &str) -> Self {
        let digest: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
        Self::from_bytes(&digest)
    }

    /// Builds a generator seeded from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// [`Error::Entropy`] when the operating system cannot provide entropy.
    pub fn from_entropy() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(Error::Entropy)?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Builds a generator from a raw xoshiro256** state.
    ///
    /// The all-zero state, on which xoshiro would emit zeros forever, is
    /// replaced by a fixed non-zero one.
    #[must_use]
    pub fn from_state(state: [u64; 4]) -> Self {
        if state == [0; 4] {
            Self {
                state: NONZERO_STATE,
            }
        } else {
            Self { state }
        }
    }

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut state = [0u64; 4];
        let (chunks, _) = bytes.as_chunks::<8>();
        for (word, chunk) in state.iter_mut().zip(chunks) {
            *word = u64::from_le_bytes(*chunk);
        }
        Self::from_state(state)
    }

    /// Returns the next 64 bits of the xoshiro256** stream.
    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.state;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// Returns a uniformly distributed double in `[0, 1)` built from the top
    /// 53 bits of [`Rng::next_u64`].
    pub fn next_f64(&mut self) -> f64 {
        let bits = self.next_u64() >> 11;
        // Both halves fit a u32 exactly, and their recombination stays below
        // 2^53, so the conversion is exact.
        let high = u32::try_from(bits >> 32).map_or(0.0, f64::from);
        let low = u32::try_from(bits & 0xFFFF_FFFF).map_or(0.0, f64::from);
        (high * 4_294_967_296.0 + low) * F64_UNIT
    }
}
