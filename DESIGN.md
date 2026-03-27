# Cryption: System Design & Architecture

## 1. System Overview
Cryption is designed as a **Layered Architecture**. This ensures that the core cryptographic logic (The Chained Algorithm) is completely decoupled from the interface (GUI) and the file system.

## 2. High-Level Architecture
The system is divided into four distinct layers:

| Layer | Responsibility | Key Component |
| :--- | :--- | :--- |
| **Interface Layer** | Handles user input via GUI. | `cryption_gui` |
| **Orchestration Layer** | Manages data flow and error handling. | `CryptionManager` |
| **Security Core** | Rust implementation of the Chained Algorithm. | `ChainedEngine` |
| **Storage Layer** | High-performance byte-stream I/O. | `FileHandler` |

---

## 3. Data Flow (Encrypt-then-MAC)
To prevent side-channel attacks, Cryption follows the Encrypt-then-MAC pipeline:

1.  **Ingestion:** User provides a raw file/string and a passkey.
2.  **Key Stretching:** **Argon2** (via the `argon2` crate) generates a high-entropy seed.  
3.  **Initialization:** The `ChainedEngine` uses the seed to shuffle the $16 \times 16$ matrix.
4.  **Transformation:** Data is processed in blocks. Each block's state is "chained" to the next.
5.  **Encapsulation:** Ciphertext is wrapped with a header (Salt, Version, Nonce).
6.  **Authentication:** An **HMAC-SHA256** is calculated over the entire package and appended.

---

## 4. Class Design (Modular Strategy)
Designing with **SOLID principles** makes the code easier to test.

### `ChainedEngine` (The Brain)
* `new(seed, nonce)`: Mixing logic ensures unique per-session LCG sequence.
* `shuffle_matrix()`: Fisher-Yates shuffle randomized by LCG state.
* `encrypt_byte(plaintext)` / `decrypt_byte(ciphertext)`: Dynamic offset substitution with integrated chaining.

### `Vault` (The Key Manager)
* `derive_argon2_keys(passkey, salt)`: Key stretching via Argon2id.
* `calculate_mac(key, data)` / `verify_mac_from_file(key, path)`: Integrity verification.

### `CryptionFormat` (The File Spec)
| Offset | Field | Size (Bytes) |
| :--- | :--- | :--- |
| 0 | Magic Bytes (CRYP) | 4 |
| 4 | Version Number | 2 |
| 6 | Argon2id Salt | 16 |
| 22 | Session Nonce | 12 |
| 34 | Encrypted Payload | Variable |
| End | HMAC-SHA256 | 32 |

---

## 5. Security Model & Threats
Defined the threat model to handle risks:

* **Brute Force Protection:** Mitigated by Argon2id cost parameters.
* **Tamper Resistance:** Mitigated by Encrypt-then-MAC; the system verifies the HMAC before decryption.
* **Replay Attacks:** Mitigated by unique per-session Nonces.

---

## 6. Tech Stack Justification
* **Language:** Rust — Chosen for memory safety and zero-cost abstractions, ensuring performance without the risk of buffer overflows.
* **KDF:** **Argon2id** — The industry standard for password hashing, resistant to GPU-based brute-force attacks.
* **Hashing:** **SHA-256** — High-speed, cryptographically secure integrity checks via the sha2 crate.