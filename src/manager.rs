// src/manager.rs
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use rand_core::{OsRng, RngCore};

use crate::engine::ChainedEngine;
use crate::format::CryptionHeader;
use crate::vault::Vault;
use crate::file_handler::FileHandler;

pub struct CryptionManager;

impl CryptionManager {
    /// Orchestrates the full Encrypt-then-MAC pipeline.
    pub fn encrypt_file(input_path: &str, output_path: &str, passkey: &str) -> Result<(), String> {
        // 1. Generate secure random Salt and Nonce
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        // 2. Initialize the Cryptographic Engine
        let seed = ChainedEngine::derive_argon2_seed(passkey, &salt);
        let mut engine = ChainedEngine::new(seed, nonce);
        engine.shuffle_matrix();

        // 3. Create and write the File Header
        let header = CryptionHeader::new(salt, nonce);
        let mut out_file = File::create(output_path).map_err(|e| e.to_string())?;
        out_file.write_all(&header.to_bytes()).map_err(|e| e.to_string())?;
        
        // We drop the file handle here so FileHandler can open it for appending
        drop(out_file); 

        // 4. Stream the file through the Engine
        FileHandler::process_file(input_path, output_path, &mut engine, true)
            .map_err(|e| e.to_string())?;

        // 5. Encrypt-then-MAC: Calculate HMAC over the entire resulting file
        let mut completed_file = OpenOptions::new().read(true).append(true).open(output_path).map_err(|e| e.to_string())?;
        let mut file_data = Vec::new();
        completed_file.read_to_end(&mut file_data).map_err(|e| e.to_string())?;

        // In a production app for massive files, the MAC would be calculated via streaming.
        // For this phase, reading the file data to memory works perfectly.
        let auth_key = passkey.as_bytes(); // Using passkey as auth key for simplicity in Phase 2
        let mac_signature = Vault::calculate_mac(auth_key, &file_data);

        // 6. Append the 32-byte MAC to the very end
        completed_file.write_all(&mac_signature).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Orchestrates the Decryption and Verification pipeline.
    pub fn decrypt_file(input_path: &str, output_path: &str, passkey: &str) -> Result<(), String> {
        let mut in_file = File::open(input_path).map_err(|e| e.to_string())?;
        let file_size = in_file.metadata().map_err(|e| e.to_string())?.len();

        if file_size < (CryptionHeader::SIZE as u64 + 32) {
            return Err("File is too small to be a valid .cryp file".into());
        }

        // 1. Read the entire file to verify integrity before doing any decryption
        let mut full_data = Vec::new();
        in_file.read_to_end(&mut full_data).map_err(|e| e.to_string())?;

        let payload_len = full_data.len() - 32;
        let file_payload = &full_data[..payload_len];
        let mut expected_mac = [0u8; 32];
        expected_mac.copy_from_slice(&full_data[payload_len..]);

        // 2. Verify HMAC to ensure no tampering occurred
        let auth_key = passkey.as_bytes();
        Vault::verify_mac(auth_key, file_payload, &expected_mac)?;

        // 3. Extract and parse the Header
        let header = CryptionHeader::from_bytes(&file_payload[..CryptionHeader::SIZE])?;

        // 4. Initialize the Engine with recovered Salt and Nonce
        let seed = ChainedEngine::derive_argon2_seed(passkey, &header.salt);
        let mut engine = ChainedEngine::new(seed, header.nonce);
        engine.shuffle_matrix();

        // 5. We need a temporary file containing just the ciphertext for the FileHandler
        // Since FileHandler expects a path, we write the ciphertext to a temp file
        let temp_path = format!("{}.tmp", input_path);
        let mut temp_file = File::create(&temp_path).map_err(|e| e.to_string())?;
        temp_file.write_all(&file_payload[CryptionHeader::SIZE..]).map_err(|e| e.to_string())?;
        drop(temp_file);

        // 6. Stream the ciphertext through the decryption engine
        FileHandler::process_file(&temp_path, output_path, &mut engine, false)
            .map_err(|e| e.to_string())?;

        // Clean up the temporary file
        std::fs::remove_file(&temp_path).map_err(|e| e.to_string())?;

        Ok(())
    }
}