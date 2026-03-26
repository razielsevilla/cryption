use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ChainedEngine {
    pub matrix: [u8; 256],    
    pub lcg_state: u64,       
    pub nonce: [u8; 12],      
}

impl ChainedEngine {
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

    pub fn next_u64(&mut self) -> u64 {
        let a: u64 = 6364136223846793005;
        let c: u64 = 1442695040888963407;
        self.lcg_state = self.lcg_state.wrapping_mul(a).wrapping_add(c);
        self.lcg_state
    }

}