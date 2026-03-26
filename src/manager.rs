// src/manager.rs
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use rand::{RngCore, rngs::OsRng};

use crate::engine::ChainedEngine;
use crate::format::CryptionHeader;
use crate::vault::Vault;
use crate::file_handler::FileHandler;
use crate::error::CryptionError; // NEW: Import our custom error enum

use base64::{Engine as _, engine::general_purpose::STANDARD};

pub struct CryptionManager;

impl CryptionManager {
    /// Orchestrates the full Encrypt-then-MAC pipeline.
    pub fn encrypt_file<F>(
        input_path: &str, 
        output_path: &str, 
        passkey: &str,
        progress_callback: Option<F>
    ) -> Result<(), CryptionError>
    where
        F: FnMut(u64),
    {
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
        
        // ? automatically converts std::io::Error to CryptionError::IoError
        let mut out_file = File::create(output_path)?; 
        out_file.write_all(&header.to_bytes())?;
        
        // We drop the file handle here so FileHandler can open it for appending
        drop(out_file); 

        // 4. Stream the file through the Engine
        FileHandler::process_file(input_path, output_path, &mut engine, true, 0, None, progress_callback)?;

        // 5. Encrypt-then-MAC: Calculate HMAC over the entire resulting file using streaming
        let mac_signature = Vault::calculate_mac_from_file(&mac_key, output_path)
            .map_err(|_| CryptionError::InvalidMAC)?; // Map MAC failures to our custom error

        // 6. Append the 32-byte MAC to the very end
        let mut completed_file = OpenOptions::new()
            .append(true)
            .open(output_path)?;
            
        completed_file.write_all(&mac_signature)?;

        Ok(())
    }

    pub fn decrypt_file<F>(
        input_path: &str, 
        output_path: &str, 
        passkey: &str,
        progress_callback: Option<F>
    ) -> Result<(), CryptionError>
    where
        F: FnMut(u64),
    {
        // 1. Extract and parse the Header
        let mut in_file = File::open(input_path)?;
        let mut header_bytes = [0u8; CryptionHeader::SIZE];
        in_file.read_exact(&mut header_bytes)?;
        
        let header = CryptionHeader::from_bytes(&header_bytes)
            .map_err(|e| CryptionError::InvalidFormat(e.to_string()))?;

        // 2. Derive keys and 3. Verify HMAC
        let (seed, mac_key) = ChainedEngine::derive_argon2_keys(passkey, &header.salt);
        
        Vault::verify_mac_from_file(&mac_key, input_path)
            .map_err(|_| CryptionError::InvalidMAC)?;

        // 4. Initialize the Engine
        let mut engine = ChainedEngine::new(seed, header.nonce);
        engine.shuffle_matrix();

        // FIX: Create the output file here to ensure it exists and is empty before decryption.
        File::create(output_path)?;

        // 5. Stream the ciphertext through the decryption engine
        let file_size = in_file.metadata()?.len();
        
        // Use saturating_sub to avoid potential underflow panics if the file was truncated
        let payload_size = file_size.saturating_sub(CryptionHeader::SIZE as u64 + 32);

        FileHandler::process_file(
            input_path,
            output_path,
            &mut engine,
            false,
            CryptionHeader::SIZE as u64,
            Some(payload_size),
            progress_callback
        )?;

        Ok(())
    }

    /// Encrypts a raw string and returns a Base64 encoded payload
    pub fn encrypt_text(text: &str, passkey: &str) -> Result<String, CryptionError> {
        // 1. Generate secure random Salt and Nonce
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        // 2. Initialize the Cryptographic Engine
        let (seed, mac_key) = ChainedEngine::derive_argon2_keys(passkey, &salt);
        let mut engine = ChainedEngine::new(seed, nonce);
        engine.shuffle_matrix();

        // 3. Create Header and initialize the payload buffer
        let header = CryptionHeader::new(salt, nonce);
        let mut payload = header.to_bytes().to_vec();

        // 4. Encrypt the text bytes
        for &byte in text.as_bytes() {
            payload.push(engine.encrypt_byte(byte));
        }

        // 5. Encrypt-then-MAC: Calculate HMAC over the header + ciphertext
        let mac_signature = Vault::calculate_mac(&mac_key, &payload);
        
        // 6. Append the MAC and encode to Base64
        payload.extend_from_slice(&mac_signature);
        Ok(STANDARD.encode(payload))
    }

    /// Decrypts a Base64 encoded payload back into a UTF-8 string
    pub fn decrypt_text(base64_text: &str, passkey: &str) -> Result<String, CryptionError> {
        // 1. Decode Base64 back to raw bytes
        let payload = STANDARD.decode(base64_text)
            .map_err(|_| CryptionError::InvalidFormat("Invalid Base64 format.".into()))?;

        if payload.len() < CryptionHeader::SIZE + 32 {
            return Err(CryptionError::InvalidFormat("Payload too small to be valid.".into()));
        }

        // 2. Extract and parse the Header
        let (header_bytes, _) = payload.split_at(CryptionHeader::SIZE);
        let header = CryptionHeader::from_bytes(header_bytes)
            .map_err(|e| CryptionError::InvalidFormat(e.to_string()))?;

        // 3. Derive keys
        let (seed, mac_key) = ChainedEngine::derive_argon2_keys(passkey, &header.salt);

        // 4. Verify MAC against the data (Header + Ciphertext)
        let mac_start = payload.len() - 32;
        let (data_to_verify, expected_mac) = payload.split_at(mac_start);
        
        let mut mac_array = [0u8; 32];
        mac_array.copy_from_slice(expected_mac);
        
        Vault::verify_mac(&mac_key, data_to_verify, &mac_array)
            .map_err(|_| CryptionError::InvalidMAC)?;

        // 5. Initialize the Engine
        let mut engine = ChainedEngine::new(seed, header.nonce);
        engine.shuffle_matrix();

        // 6. Decrypt the ciphertext
        let ciphertext = &data_to_verify[CryptionHeader::SIZE..];
        let mut decrypted_bytes = Vec::with_capacity(ciphertext.len());

        for &byte in ciphertext {
            decrypted_bytes.push(engine.decrypt_byte(byte));
        }

        // 7. Convert back to a String
        String::from_utf8(decrypted_bytes)
            .map_err(|_| CryptionError::InvalidFormat("Decrypted data is not valid UTF-8.".into()))
    }
}