use zeroize::Zeroize;

// Requirement 3: Implement the Zeroize trait to clear sensitive data from RAM
#[derive(Zeroize)]
#[zeroize(drop)] // This ensures data is wiped when the struct goes out of scope
pub struct ChainedEngine {
    // Requirement 1: Define a matrix field
    pub matrix: [u8; 256],    
    
    // Requirement 2: Add lcg_state and nonce fields
    pub lcg_state: u64,       
    pub nonce: [u8; 12],      
}