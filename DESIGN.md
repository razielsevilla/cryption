# Cryption: System Design & Architecture

## 1. System Overview
Cryption is designed as a **Layered Architecture**. This ensures that the core cryptographic logic (The Chained Algorithm) is completely decoupled from the interface (GUI) and the file system.

## 2. High-Level Architecture
The system is divided into four distinct layers:

| Layer | Responsibility | Key Component |
| :--- | :--- | :--- |
| **Interface Layer** | Handles user input/output. | `CryptionGUI` |
| **Orchestration Layer** | Manages the flow between keys, files, and the engine. | `CryptionManager` |
| **Security Core** | The mathematical implementation of the algorithm. | `ChainedEngine` |
| **Storage Layer** | Handles byte-stream I/O and custom file formatting. | `FileHandler` |

---

## 3. Data Flow (The Encryption Pipeline)
To ensure security, data follows a strict one-way pipeline during encryption:

1.  **Ingestion:** User provides a raw file/string and a passkey.
2.  **Key Stretching:** The passkey is fed into **Argon2id** (KDF) to generate a high-entropy seed.
3.  **Initialization:** The `ChainedEngine` uses the seed to shuffle the $10 \times 10$ matrix.
4.  **Transformation:** Data is processed in blocks. Each block's state is "chained" to the next.
5.  **Encapsulation:** The ciphertext is wrapped with a header (Salt, IV, Algorithm Version).
6.  **Authentication:** An **HMAC-SHA256** is calculated over the entire package and appended.

---

## 4. Class Design (Modular Strategy)
Designing with **SOLID principles** makes the code easier to test.

### `ChainedEngine` (The Brain)
* `generate_matrix(seed)`: Creates the initial $10 \times 10$ state.
* `shuffle_rounds(n)`: Executes the LCG-driven permutation.
* `transform(byte_block)`: The core XOR/Substitution logic.

### `Vault` (The Key Manager)
* `derive_key(password, salt)`: Handles the KDF logic.
* `verify_integrity(file_data)`: Checks the HMAC before decryption.

### `CryptionFormat` (The File Spec)
Defines the structure of the `.cryp` file:
* **Bytes 0-3:** Magic Bytes (`CRYP`)
* **Bytes 4-5:** Version Number
* **Bytes 6-22:** Salt (16 bytes)
* **Bytes 23-55:** HMAC Signature
* **Bytes 56+:** Encrypted Payload

---

## 5. Security Model & Threats
Defined the threat model to handle risks:

* **Brute Force Protection:** Mitigated by using **Argon2id** with high memory/time costs, making "guessing" computationally expensive.
* **Tamper Resistance:** Mitigated by the **HMAC** layer. If a single bit of the file is changed, the system refuses to decrypt.
* **Known Plaintext Attack:** Mitigated by **Cipher Chaining**. Identical inputs result in different outputs based on their position in the stream.

---

## 6. Tech Stack Justification
* **Language:** Python — Chosen for its ability to handle low-level byte manipulation efficiently.
* **KDF:** **Argon2id** — Current industry standard for password hashing (winner of the Password Hashing Competition).
* **Hashing:** **SHA-256** — Reliable and widely supported for integrity checks.