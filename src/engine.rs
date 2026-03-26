use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ChainedEngine {
    pub matrix: [u8; 256],    
    pub lcg_state: u64,       
    pub nonce: [u8; 12],      
}

impl ChainedEngine {
    /// P1-03: Polynomial Hash Implementation
    /// Converts a passkey string into a u64 seed for the LCG.
    pub fn derive_polynomial_hash(passkey: &str) -> u64 {
        let p: u64 = 53;
        let mut hash: u64 = 0;

        for (i, c) in passkey.chars().enumerate() {
            let char_val = c as u64;
            let power = p.wrapping_pow(i as u32);
            let term = char_val.wrapping_mul(power);
            hash = hash.wrapping_add(term);
        }

        hash
    }
}