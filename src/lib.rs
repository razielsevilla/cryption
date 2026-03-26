pub mod engine;
pub mod format;
pub mod vault;
pub mod file_handler;
pub mod manager;

#[cfg(test)]
mod engine_tests {
    use crate::engine::ChainedEngine;
    use crate::format::CryptionHeader;
    use crate::vault::Vault;

    /// P1-03: Verifies that the same passkey always produces the same seed.
    /// This ensures the polynomial rolling hash is deterministic.
    #[test]
    fn test_polynomial_hash_consistency() {
        let key = "secure_password";
        let hash1 = ChainedEngine::derive_polynomial_hash(key);
        let hash2 = ChainedEngine::derive_polynomial_hash(key);
        assert_eq!(hash1, hash2, "Polynomial hashes must be consistent for the same key");
    }

    /// P1-05: Verifies that the Fisher-Yates shuffle randomizes the matrix correctly.
    /// Ensures a unique 16x16 state space is generated.
    #[test]
    fn test_matrix_shuffling_integrity() {
        let seed = 987654321;
        let nonce = [0u8; 12];
        let mut engine = ChainedEngine::new(seed, nonce);
        
        let original_matrix = engine.matrix; // Initially all zeros
        engine.shuffle_matrix();
        
        // 1. Verify the matrix has changed from its initial state
        assert_ne!(original_matrix, engine.matrix, "Matrix should be randomized after shuffle");
        
        // 2. Verify it is still a valid permutation (all 256 bytes present)
        let mut sorted_matrix = engine.matrix;
        sorted_matrix.sort();
        let expected: Vec<u8> = (0..=255).collect();
        assert_eq!(sorted_matrix.to_vec(), expected, "Matrix must contain all values from 0 to 255");
    }

    /// P1-06 & P2-01: The "Phase 1 Conclusion" Round-Trip Test.
    /// Verifies that data can be encrypted and then decrypted back using Argon2 seeds.
    #[test]
    fn test_encryption_decryption_round_trip() {
        let passkey = "Zie_Cryption_2026";
        let salt = [0u8; 16];
        let nonce = [0u8; 12]; // Defined before use in the engines below
        
        // P2-01: Key Stretching via Argon2id
        let seed = ChainedEngine::derive_argon2_seed(passkey, &salt);
        let message = b"Confidential Thesis Data";

        // 1. Encryption Side
        let mut encryptor = ChainedEngine::new(seed, nonce);
        encryptor.shuffle_matrix();
        let ciphertext: Vec<u8> = message.iter().map(|&b| encryptor.encrypt_byte(b)).collect();

        // 2. Decryption Side (Must start from the same seed and nonce)
        let mut decryptor = ChainedEngine::new(seed, nonce);
        decryptor.shuffle_matrix();
        let decrypted: Vec<u8> = ciphertext.iter().map(|&b| decryptor.decrypt_byte(b)).collect();

        // 3. Verification
        assert_eq!(message.to_vec(), decrypted, "Decrypted bytes must match the original plaintext");
        assert_ne!(message.to_vec(), ciphertext, "Ciphertext must not match plaintext (encryption failed)");
    }

    #[test]
    fn test_header_serialization() {
        // 1. Setup mock data
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        
        // 2. Initialize using the constructor to ensure Magic Bytes and Version are set
        let original = CryptionHeader::new(salt, nonce);
        
        // 3. Serialize using the method we defined
        let bytes = original.to_bytes();
        
        // 4. Deserialize and unwrap the Result
        let recovered = CryptionHeader::from_bytes(&bytes).expect("Failed to deserialize valid header bytes");
        
        // 5. Verify all fields match
        assert_eq!(original.magic, recovered.magic, "Magic bytes must match");
        assert_eq!(original.version, recovered.version, "Version must match");
        assert_eq!(original.salt, recovered.salt, "Salt must match");
        assert_eq!(original.nonce, recovered.nonce, "Nonce must match");
    }

    /// P2-03: Verifies that the HMAC layer catches data tampering
    #[test]
    fn test_hmac_integrity() {
        let auth_key = b"super_secret_authentication_key";
        let valid_file_data = b"CRYP\x02\x00...pretend_this_is_header_and_ciphertext...";
        
        // 1. Calculate the MAC for our valid file
        let valid_mac = Vault::calculate_mac(auth_key, valid_file_data);
        
        // 2. Verification should pass for the exact same data
        let verify_success = Vault::verify_mac(auth_key, valid_file_data, &valid_mac);
        assert!(verify_success.is_ok(), "MAC verification should pass for untampered data");

        // 3. Simulate an attacker tampering with the file (changing one byte)
        let mut tampered_file_data = valid_file_data.to_vec();
        tampered_file_data[10] = b'X'; 
        
        // 4. Verification MUST fail for the tampered data
        let verify_fail = Vault::verify_mac(auth_key, &tampered_file_data, &valid_mac);
        assert!(verify_fail.is_err(), "MAC verification MUST fail if data is altered");
    }
}