// src/manager.rs
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use rand::{RngCore, rngs::OsRng};

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
        let (seed, mac_key) = ChainedEngine::derive_argon2_keys(passkey, &salt);
        let mut engine = ChainedEngine::new(seed, nonce);
        engine.shuffle_matrix();

        // 3. Create and write the File Header
        let header = CryptionHeader::new(salt, nonce);
        let mut out_file = File::create(output_path).map_err(|e| e.to_string())?;
        out_file.write_all(&header.to_bytes()).map_err(|e| e.to_string())?;
        
        // We drop the file handle here so FileHandler can open it for appending
        drop(out_file); 

        // 4. Stream the file through the Engine
        FileHandler::process_file(input_path, output_path, &mut engine, true, 0, None)
            .map_err(|e| e.to_string())?;

        // 5. Encrypt-then-MAC: Calculate HMAC over the entire resulting file using streaming
        let mac_signature = Vault::calculate_mac_from_file(&mac_key, output_path)
            .map_err(|e| e.to_string())?;

        // 6. Append the 32-byte MAC to the very end
        let mut completed_file = OpenOptions::new()
            .append(true)
            .open(output_path)
            .map_err(|e| e.to_string())?;
            
        completed_file.write_all(&mac_signature).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Orchestrates the Decryption and Verification pipeline.
    pub fn decrypt_file(input_path: &str, output_path: &str, passkey: &str) -> Result<(), String> {
        // 1. Extract and parse the Header to get the salt for Argon2
        let mut in_file = File::open(input_path).map_err(|e| e.to_string())?;
        let mut header_bytes = [0u8; CryptionHeader::SIZE];
        in_file.read_exact(&mut header_bytes).map_err(|_| "Failed to read header. File may be too small or corrupted.")?;
        let header = CryptionHeader::from_bytes(&header_bytes)?;

        // 2. Derive independent keys
        let (seed, mac_key) = ChainedEngine::derive_argon2_keys(passkey, &header.salt);

        // 3. Verify HMAC via streaming, preventing full-file memory load or tampering mid-decryption
        Vault::verify_mac_from_file(&mac_key, input_path)?;

        // 4. Initialize the Engine with recovered Seed and Nonce
        let mut engine = ChainedEngine::new(seed, header.nonce);
        engine.shuffle_matrix();

        // 5. Stream the ciphertext through the decryption engine directly from the input file
        // We calculate the exact payload size to avoid processing the HMAC signature as cipher data
        let file_size = in_file.metadata().map_err(|e| e.to_string())?.len();
        let payload_size = file_size - CryptionHeader::SIZE as u64 - 32;

        FileHandler::process_file(
            input_path,
            output_path,
            &mut engine,
            false,
            CryptionHeader::SIZE as u64,
            Some(payload_size)
        ).map_err(|e| e.to_string())?;

        Ok(())
    }
}