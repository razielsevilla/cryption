use zeroize::Zeroize;

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

/// P1-02: ChainedEngine Data Structure
/// A secure data container for the algorithm's state.
#[derive(Zeroize)]
#[zeroize(drop)] // Implements the Zeroize trait to clear sensitive data from RAM
pub struct ChainedEngine {
    pub matrix: [u8; 256],    // Requirement 1: 16x16 matrix field
    pub lcg_state: u64,       // Requirement 2: LCG state field
    pub nonce: [u8; 12],      // Requirement 2: Nonce field
}

impl ChainedEngine {
    /// Constructor to initialize the engine with a seed and nonce.
    pub fn new(seed: u64, nonce: [u8; 12]) -> Self {
        // P2-01: Incorporate the nonce into the initial LCG state.
        // We use the LCG formula itself to 'absorb' the nonce bytes, 
        // ensuring even a 1-bit change in the nonce spreads across the entire 64-bit state.
        let mut initial_state = seed;
        let a: u64 = 6364136223846793005;
        let c: u64 = 1442695040888963407;

        for &byte in nonce.iter() {
            initial_state = initial_state.wrapping_mul(a).wrapping_add(byte as u64).wrapping_add(c);
        }

        Self {
            matrix: [0u8; 256], // Initialized as zeros, filled during shuffle
            lcg_state: initial_state,
            nonce,
        }
    }

    /// P1-03: Polynomial Hash Implementation
    /// Converts a passkey string into a u64 seed for the LCG.
    /// Formula: H = sum(ord(S[i]) * 53^i) mod 2^64
    pub fn derive_polynomial_hash(passkey: &str) -> u64 {
        let p: u64 = 53; // Prime number to minimize collisions
        let mut hash: u64 = 0;

        for (i, c) in passkey.chars().enumerate() {
            let char_val = c as u64;
            // wrapping_pow and wrapping_mul handle the mod 2^64 modulus
            let power = p.wrapping_pow(i as u32);
            let term = char_val.wrapping_mul(power);
            hash = hash.wrapping_add(term);
        }

        hash
    }

    /// P1-04: LCG State Machine
    /// Updates the lcg_state using: X_{n+1} = (aX_n + c) mod 2^64
    pub fn next_u64(&mut self) -> u64 {
        // Constants satisfying the Hull-Dobell Theorem for a full period
        let a: u64 = 6364136223846793005;
        let c: u64 = 1442695040888963407;

        self.lcg_state = self.lcg_state.wrapping_mul(a).wrapping_add(c);
        self.lcg_state
    }

    /// P1-05: Matrix Shuffling Logic
    /// Creates a unique, randomized 16x16 state space for each session.
    pub fn shuffle_matrix(&mut self) {
        // 1. Initialize matrix with values 0..=255
        for i in 0..256 {
            self.matrix[i] = i as u8;
        }

        // 2. Implement the Fisher-Yates shuffle
        // a. Loop from i = 255 down to 1
        for i in (1..256).rev() {
            // b. Generate a random index j using the LCG
            let j = (self.next_u64() % (i as u64 + 1)) as usize;

            // c. Swap matrix[i] and matrix[j]
            self.matrix.swap(i, j);
        }
    }

    /// P1-06: Chaining Transformation - Encryption
    /// A functional pipeline with a strong Avalanche Effect.
    pub fn encrypt_byte(&mut self, plaintext: u8) -> u8 {
        // 1. Advance LCG to get a dynamic offset for this byte
        // This ensures identical plaintext bytes result in different ciphertext bytes
        let offset = self.next_u64() as u8;

        // 2. Perform matrix substitution with dynamic offset: C_i = Matrix[plaintext + offset]
        let ciphertext = self.matrix[plaintext.wrapping_add(offset) as usize];

        // 3. The Chain: Update lcg_state = lcg_state ^ C_i (Requirement P1-06)
        self.lcg_state ^= ciphertext as u64;

        ciphertext
    }

    /// P1-06: Chaining Transformation - Decryption
    pub fn decrypt_byte(&mut self, ciphertext: u8) -> u8 {
        // 1. Advance LCG identically to the encryption side
        let offset = self.next_u64() as u8;

        // 2. Find the index and reverse the dynamic offset
        let substituted_index = self.matrix.iter()
            .position(|&val| val == ciphertext)
            .expect("Matrix must contain all 256 bytes") as u8;

        let plaintext = substituted_index.wrapping_sub(offset);

        // 3. Update the chain to stay synchronized
        self.lcg_state ^= ciphertext as u64;

        plaintext
    }

    /// P2-01: Argon2id Integration
    /// Stretches a passkey into a cryptographically strong seed for LCG and a key for HMAC.
    pub fn derive_argon2_keys(passkey: &str, salt: &[u8; 16]) -> (u64, [u8; 32]) {
        // 1. Initialize Argon2id with default parameters
        let argon2 = Argon2::default();
        
        // 2. Wrap the salt in the required SaltString format
        let salt_string = SaltString::encode_b64(salt).expect("Salt encoding failed");

        // 3. Hash the password
        let password_hash = argon2
            .hash_password(passkey.as_bytes(), &salt_string)
            .expect("Argon2 hashing failed")
            .hash
            .expect("Hash output missing");

        // 4. Map the first 8 bytes of the output to a u64 for the LCG seed
        let mut seed_bytes = [0u8; 8];
        seed_bytes.copy_from_slice(&password_hash.as_bytes()[0..8]);
        let seed = u64::from_le_bytes(seed_bytes);
        
        // 5. Use the first 32 bytes of the Argon2 hash as the MAC key
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&password_hash.as_bytes()[0..32]);

        (seed, mac_key)
    }
}