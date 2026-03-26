pub mod engine;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

#[cfg(test)]
mod engine_tests {
    use crate::engine::ChainedEngine;

    #[test]
    fn test_polynomial_hash_consistency() {
        let key = "secure_password";
        let hash1 = ChainedEngine::derive_polynomial_hash(key);
        let hash2 = ChainedEngine::derive_polynomial_hash(key);
        assert_eq!(hash1, hash2);
    }
}