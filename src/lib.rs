pub mod engine;

#[cfg(test)]
mod engine_tests {
    use crate::engine::ChainedEngine;

    #[test]
    fn test_polynomial_hash_consistency() {
        let key = "secure_password";
        let hash1 = ChainedEngine::derive_polynomial_hash(key);
        let hash2 = ChainedEngine::derive_polynomial_hash(key);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_matrix_shuffling_integrity() {
        // Initialize engine with a seed and a dummy nonce
        let seed = 987654321;
        let nonce = [0u8; 12];
        let mut engine = ChainedEngine::new(seed, nonce);
        
        // Capture the identity matrix (0..255) before shuffling
        let original_matrix = engine.matrix;
        
        // Execute the Fisher-Yates shuffle
        engine.shuffle_matrix();
        
        // 1. Verify the matrix has actually changed
        assert_ne!(original_matrix, engine.matrix, "Matrix should be randomized after shuffle");
        
        // 2. Verify it is still a valid permutation (all 256 bytes present)
        let mut sorted_matrix = engine.matrix;
        sorted_matrix.sort();
        let expected: Vec<u8> = (0..=255).collect();
        assert_eq!(sorted_matrix.to_vec(), expected, "Matrix must contain all values from 0 to 255");
    }
}