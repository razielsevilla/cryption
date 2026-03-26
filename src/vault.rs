// src/vault.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

// Create an alias to simplify our HMAC-SHA256 type
type HmacSha256 = Hmac<Sha256>;

pub struct Vault;

impl Vault {
    /// P2-03: Calculates the HMAC-SHA256 signature over the provided data.
    pub fn calculate_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take a key of any size");
        mac.update(data);
        
        let result = mac.finalize();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&result.into_bytes());
        mac_bytes
    }

    /// P2-03: Verifies if the provided MAC matches the calculated MAC for the data.
    pub fn verify_mac(key: &[u8], data: &[u8], expected_mac: &[u8; 32]) -> Result<(), &'static str> {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take a key of any size");
        mac.update(data);
        
        match mac.verify_slice(expected_mac) {
            Ok(_) => Ok(()),
            Err(_) => Err("Integrity check failed: Data has been tampered with or key is incorrect"),
        }
    }

    /// Calculates expected MAC from file via streaming to prevent memory exhaustion
    pub fn calculate_mac_from_file(key: &[u8], file_path: &str) -> std::io::Result<[u8; 32]> {
        let mut file = File::open(file_path)?;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take a key of any size");
        let mut buffer = [0u8; 4096];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            mac.update(&buffer[..n]);
        }
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&mac.finalize().into_bytes());
        Ok(mac_bytes)
    }

    /// Verifies the MAC by streaming the first `file_size - 32` bytes of the file.
    pub fn verify_mac_from_file(key: &[u8], file_path: &str) -> Result<(), String> {
        let mut file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;
        let metadata = file.metadata().map_err(|e| format!("Failed to read metadata: {}", e))?;
        let file_size = metadata.len();
        if file_size < 34 + 32 {
            return Err("File too small to be a valid .cryp file".into());
        }
        
        let payload_size = file_size - 32;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take a key of any size");
        let mut buffer = [0u8; 4096];
        let mut bytes_processed = 0u64;
        
        loop {
            let remaining = payload_size - bytes_processed;
            if remaining == 0 { break; }
            
            let to_read = std::cmp::min(buffer.len() as u64, remaining) as usize;
            let n = file.read(&mut buffer[..to_read]).map_err(|e| format!("Failed to read file chunk: {}", e))?;
            
            if n == 0 { break; } // Unexpected EOF
            
            mac.update(&buffer[..n]);
            bytes_processed += n as u64;
        }
        
        if bytes_processed != payload_size {
            return Err("Failed to read the entire file payload".into());
        }
        
        let mut expected_mac = [0u8; 32];
        file.seek(SeekFrom::Start(payload_size)).map_err(|e| format!("Failed to seek to MAC: {}", e))?;
        file.read_exact(&mut expected_mac).map_err(|e| format!("Failed to read MAC: {}", e))?;
        
        match mac.verify_slice(&expected_mac) {
            Ok(_) => Ok(()),
            Err(_) => Err("Integrity check failed: Data has been tampered with or key is incorrect".into()),
        }
    }
}