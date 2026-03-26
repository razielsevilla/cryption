// src/vault.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Create an alias to simplify our HMAC-SHA256 type
type HmacSha256 = Hmac<Sha256>;

pub struct Vault;

impl Vault {
    /// P2-03: Calculates the HMAC-SHA256 signature over the provided data.
    /// In practice, `data` will be a buffer containing [Header + Ciphertext].
    pub fn calculate_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        // Initialize the HMAC with the provided key
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take a key of any size");
        
        // Feed the data into the HMAC engine
        mac.update(data);
        
        // Extract the final 32-byte signature
        let result = mac.finalize();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(&result.into_bytes());
        
        mac_bytes
    }

    /// P2-03: Verifies if the provided MAC matches the calculated MAC for the data.
    /// Uses constant-time equality checks to prevent timing attacks.
    pub fn verify_mac(key: &[u8], data: &[u8], expected_mac: &[u8; 32]) -> Result<(), &'static str> {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take a key of any size");
        
        mac.update(data);
        
        // verify_slice performs a secure, constant-time comparison
        match mac.verify_slice(expected_mac) {
            Ok(_) => Ok(()),
            Err(_) => Err("Integrity check failed: Data has been tampered with or key is incorrect"),
        }
    }
}