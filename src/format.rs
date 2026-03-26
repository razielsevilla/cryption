// src/format.rs

#[derive(Debug, PartialEq)]
pub struct CryptionHeader {
    pub magic: [u8; 4],     // [0..4]
    pub version: u16,       // [4..6]
    pub salt: [u8; 16],     // [6..22]
    pub nonce: [u8; 12],    // [22..34]
}

impl CryptionHeader {
    pub const SIZE: usize = 34;
    pub const MAGIC: &'static [u8; 4] = b"CRYP";
    pub const VERSION: u16 = 2; // For Chained Algorithm v2.0

    /// Creates a new header with the provided salt and nonce.
    pub fn new(salt: [u8; 16], nonce: [u8; 12]) -> Self {
        Self {
            magic: *Self::MAGIC,
            version: Self::VERSION,
            salt,
            nonce,
        }
    }

    /// Serializes the header into a 34-byte array for writing to a file.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buffer = [0u8; Self::SIZE];
        
        // a. [0..4] Magic Bytes
        buffer[0..4].copy_from_slice(&self.magic);
        
        // b. [4..6] Version
        buffer[4..6].copy_from_slice(&self.version.to_le_bytes());
        
        // c. [6..22] Salt
        buffer[6..22].copy_from_slice(&self.salt);
        
        // d. [22..34] Nonce
        buffer[22..34].copy_from_slice(&self.nonce);
        
        buffer
    }

    /// Parses a 34-byte slice back into a CryptionHeader.
    /// Returns an error if the magic bytes do not match "CRYP".
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, &'static str> {
        if buffer.len() < Self::SIZE {
            return Err("Buffer too small to contain a valid header");
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buffer[0..4]);
        
        if &magic != Self::MAGIC {
            return Err("Invalid magic bytes: Not a valid .cryp file");
        }

        let mut version_bytes = [0u8; 2];
        version_bytes.copy_from_slice(&buffer[4..6]);
        let version = u16::from_le_bytes(version_bytes);

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buffer[6..22]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buffer[22..34]);

        Ok(Self {
            magic,
            version,
            salt,
            nonce,
        })
    }
}