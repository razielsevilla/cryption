use std::fmt;
use std::io;

#[derive(Debug)]
pub enum CryptionError {
    InvalidMAC,
    WrongPassword,
    FileInaccessible(String),
    InvalidFormat(String),
    IoError(io::Error),
}

// This allows the error to be printed beautifully in the CLI and GUI
impl fmt::Display for CryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptionError::InvalidMAC => write!(f, "Integrity check failed: Data has been tampered with or key is incorrect."),
            CryptionError::WrongPassword => write!(f, "Incorrect passkey provided."),
            CryptionError::FileInaccessible(path) => write!(f, "Cannot access or read the file at: {}", path),
            CryptionError::InvalidFormat(msg) => write!(f, "Invalid payload format: {}", msg),
            CryptionError::IoError(e) => write!(f, "System I/O Error: {}", e),
        }
    }
}

impl std::error::Error for CryptionError {}

// Automatically convert standard std::io::Error into our custom IoError
impl From<io::Error> for CryptionError {
    fn from(err: io::Error) -> Self {
        CryptionError::IoError(err)
    }
}