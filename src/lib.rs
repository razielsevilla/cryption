pub mod engine;

#[cfg(test)]
mod engine_tests {
    use crate::engine::ChainedEngine;

    /// P1-03: Verifies that the same passkey always produces the same seed.
    #[test]
    fn test_polynomial_hash_consistency() {
        let key = "secure_password";
        let hash1 = ChainedEngine::derive_polynomial_hash(key);
        let hash2 = ChainedEngine::derive_polynomial_hash(key);
        assert_eq!(hash1, hash2);
    }

    /// P1-05: Verifies that the Fisher-Yates shuffle randomizes the matrix correctly.
    #[test]
    fn test_matrix_shuffling_integrity() {
        let seed = 987654321;
        let nonce = [0u8; 12];
        let mut engine = ChainedEngine::new(seed, nonce);
        
        let original_matrix = engine.matrix;
        engine.shuffle_matrix();
        
        // 1. Verify the matrix has changed from its initial zero/identity state
        assert_ne!(original_matrix, engine.matrix, "Matrix should be randomized after shuffle");
        
        // 2. Verify it is still a valid permutation (all 256 bytes present)
        let mut sorted_matrix = engine.matrix;
        sorted_matrix.sort();
        let expected: Vec<u8> = (0..=255).collect();
        assert_eq!(sorted_matrix.to_vec(), expected, "Matrix must contain all values from 0 to 255");
    }

    /// P1-06: The "Phase 1 Conclusion" Round-Trip Test.
    /// Verifies that data can be encrypted and then decrypted back to its original state.
    #[test]
    fn test_encryption_decryption_round_trip() {
        let passkey = "Zie_Cryption_2026";
        let salt = [0u8; 16]; // In P2-02, this will be randomly generated and saved in the file header
        let seed = ChainedEngine::derive_argon2_seed(passkey, &salt);
        let mut engine = ChainedEngine::new(seed, nonce);
        let nonce = [0u8; 12];
        let message = b"Confidential Thesis Data"; // Byte representation of string

        // 1. Encryption Side
        let mut encryptor = ChainedEngine::new(seed, nonce);
        encryptor.shuffle_matrix();
        let ciphertext: Vec<u8> = message.iter().map(|&b| encryptor.encrypt_byte(b)).collect();

        // 2. Decryption Side (Must start from the same seed/nonce)
        let mut decryptor = ChainedEngine::new(seed, nonce);
        decryptor.shuffle_matrix();
        let decrypted: Vec<u8> = ciphertext.iter().map(|&b| decryptor.decrypt_byte(b)).collect();

        // 3. Verification
        assert_eq!(message.to_vec(), decrypted, "Decrypted bytes must match the original plaintext");
        assert_ne!(message.to_vec(), ciphertext, "Ciphertext must not be readable as plaintext");
    }
}