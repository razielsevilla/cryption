use cryption::engine::ChainedEngine;
use cryption::manager::CryptionManager;
use cryption::error::CryptionError;
use std::fs;

/// Calculates the Hamming Distance (number of differing bits) between two slices.
fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len(), "Slices must have equal length to calculate Hamming distance.");
    let mut distance = 0;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        // XOR the bytes to find differing bits
        let xor = byte_a ^ byte_b;
        // Count set bits (population count)
        distance += xor.count_ones() as usize;
    }
    distance
}

#[test]
fn test_avalanche_effect_seed_flip() {
    let original_seed: u64 = 0x123456789ABCDEFF;
    let nonce: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let plaintext = vec![0u8; 1000]; // 1000-byte file (8000 bits) for statistical relevance

    // 1. Baseline Encryption
    let mut engine1 = ChainedEngine::new(original_seed, nonce);
    engine1.shuffle_matrix();
    let ciphertext1: Vec<u8> = plaintext.iter().map(|&b| engine1.encrypt_byte(b)).collect();

    // 2. Bit-Flipped Encryption (Flip precisely 1 bit in the seed)
    let flipped_seed = original_seed ^ 1; // Flip LSB
    let mut engine2 = ChainedEngine::new(flipped_seed, nonce);
    engine2.shuffle_matrix();
    let ciphertext2: Vec<u8> = plaintext.iter().map(|&b| engine2.encrypt_byte(b)).collect();

    // 3. Calculate Hamming Distance
    let distance = hamming_distance(&ciphertext1, &ciphertext2);
    let bit_count = plaintext.len() * 8;
    let percentage = (distance as f32 / bit_count as f32) * 100.0;

    println!("Hamming Distance (Seed Flip): {} / {} bits ({:.2}%)", distance, bit_count, percentage);

    // Requirement: Ensure >50% of bits changed
    assert!(distance > bit_count / 2, "Avalanche effect must change >50% of bits (got {} bits, {:.2}%)", distance, percentage);
}

#[test]
fn test_avalanche_effect_nonce_flip() {
    let seed: u64 = 0x123456789ABCDEFF;
    let original_nonce: [u8; 12] = [0; 12];
    let plaintext = vec![0u8; 1000];

    // 1. Baseline Encryption
    let mut engine1 = ChainedEngine::new(seed, original_nonce);
    engine1.shuffle_matrix();
    let ciphertext1: Vec<u8> = plaintext.iter().map(|&b| engine1.encrypt_byte(b)).collect();

    // 2. Bit-Flipped Encryption (Flip precisely 1 bit in the nonce)
    let mut flipped_nonce = original_nonce;
    flipped_nonce[0] ^= 1; // Flip 1 bit in the first byte
    let mut engine2 = ChainedEngine::new(seed, flipped_nonce);
    engine2.shuffle_matrix();
    let ciphertext2: Vec<u8> = plaintext.iter().map(|&b| engine2.encrypt_byte(b)).collect();

    // 3. Calculate Hamming Distance
    let distance = hamming_distance(&ciphertext1, &ciphertext2);
    let bit_count = plaintext.len() * 8;
    let percentage = (distance as f32 / bit_count as f32) * 100.0;

    println!("Hamming Distance (Nonce Flip): {} / {} bits ({:.2}%)", distance, bit_count, percentage);

    // Requirement: Ensure >50% of bits changed
    assert!(distance > bit_count / 2, "Avalanche effect must change >50% of bits (got {} bits, {:.2}%)", distance, percentage);
}

#[test]
fn test_integrity_tamper_resistance() {
    let passkey = "zie_integrity_test_2026";
    let input_path = "test_integrity.bin";
    let encrypted_path = "test_integrity.bin.cryp";
    let decrypted_path = "test_integrity.bin.decrypted";

    // 1. Setup: Create a test file and encrypt it
    let plaintext = b"This is a secret message that should not be tampered with.";
    fs::write(input_path, plaintext).unwrap();

    CryptionManager::encrypt_file(input_path, encrypted_path, passkey, None::<fn(u64)>).unwrap();

    // 2. Scenario A: Tamper with a Ciphertext byte (offset 40)
    let mut encrypted_data = fs::read(encrypted_path).unwrap();
    encrypted_data[40] ^= 0xFF; // Flip all bits in one byte
    fs::write(encrypted_path, &encrypted_data).unwrap();

    let result = CryptionManager::decrypt_file(encrypted_path, decrypted_path, passkey, None::<fn(u64)>);
    assert!(matches!(result, Err(CryptionError::InvalidMAC)), "System must catch ciphertext tampering via HMAC failure");

    // 3. Scenario B: Tamper with a MAC byte (the very last byte)
    // Re-encrypt to reset ciphertext tamper
    CryptionManager::encrypt_file(input_path, encrypted_path, passkey, None::<fn(u64)>).unwrap();
    encrypted_data = fs::read(encrypted_path).unwrap();
    let last_idx = encrypted_data.len() - 1;
    encrypted_data[last_idx] ^= 0xFF;
    fs::write(encrypted_path, &encrypted_data).unwrap();

    let result = CryptionManager::decrypt_file(encrypted_path, decrypted_path, passkey, None::<fn(u64)>);
    assert!(matches!(result, Err(CryptionError::InvalidMAC)), "System must catch MAC tampering");

    // 4. Scenario C: Tamper with a Header byte (offset 10, within salt/nonce)
    CryptionManager::encrypt_file(input_path, encrypted_path, passkey, None::<fn(u64)>).unwrap();
    encrypted_data = fs::read(encrypted_path).unwrap();
    encrypted_data[10] ^= 0xFF; // Tampering with the salt/nonce should also break HMAC
    fs::write(encrypted_path, &encrypted_data).unwrap();

    let result = CryptionManager::decrypt_file(encrypted_path, decrypted_path, passkey, None::<fn(u64)>);
    assert!(matches!(result, Err(CryptionError::InvalidMAC)), "System must catch Header tampering");

    // 5. Cleanup
    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(encrypted_path);
    let _ = fs::remove_file(decrypted_path);
}
