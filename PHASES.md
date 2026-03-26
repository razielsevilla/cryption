### Phase 1: Core Engine (The Mathematical Foundation)

This phase focuses on the "Chained" logic, ensuring the $16 \times 16$ matrix and LCG are perfectly deterministic.

| ID | Task Name | Step-by-Step Technical Procedure | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **P1-01** | **Environment Setup** | 1. Initialize with `cargo init --lib`. <br> 2. Add `zeroize`, `rand_core`, and `byteorder` crates to `Cargo.toml`. <br> 3. Create `src/engine.rs` to house the algorithm logic. | A clean Rust workspace ready for systems-level coding. |
| **P1-02** | **`ChainedEngine` Data Structure** | 1. Define a `struct` with a `matrix: [u8; 256]` field. <br> 2. Add `lcg_state: u64` and `nonce: [u8; 12]` fields. <br> 3. Implement the `Zeroize` trait on the struct to clear sensitive data from RAM. | A secure data container for the algorithm's state. |
| **P1-03** | **Polynomial Hash Implementation** | 1. Create a function taking a `&str` passkey. <br> 2. Implement $H = \left( \sum_{i=0}^{n-1} \text{ord}(S[i]) \cdot 53^i \right) \pmod{2^{64}}$. <br> 3. Return a `u64` to be used as the LCG's initial seed. | A sensitive hashing utility that turns passwords into seeds. |
| **P1-04** | **LCG State Machine** | 1. Implement `next_u64()` using the LCG formula: $X_{n+1} = (aX_n + c) \pmod m$. <br> 2. Choose constants $a$ and $c$ that satisfy the Hull-Dobell Theorem for a full period. | A deterministic PRNG that drives the matrix transformations. |
| **P1-05** | **Matrix Shuffling Logic** | 1. Initialize `matrix` with values `0..=255`. <br> 2. Implement the **Fisher-Yates shuffle**: <br>     a. Loop from $i = 255$ down to $1$. <br>     b. Generate a random index $j$ using the LCG. <br>     c. Swap `matrix[i]` and `matrix[j]`. | A unique, randomized $16 \times 16$ state space for each session. |
| **P1-06** | **Chaining Transformation** | 1. Implement `encrypt_byte(plaintext: u8)`. <br> 2. Perform matrix substitution: $C_i = \text{Matrix}[\text{plaintext}]$. <br> 3. **The Chain:** Update `lcg_state = lcg_state ^ C_i` to influence the next byte's shuffle. | A functional pipeline with a strong Avalanche Effect. |

-----

### Phase 2: Security & Storage (Hardening the Platform)

In this phase, you wrap the engine in industry-standard protection: **Argon2id** and **HMAC**.

| ID | Task Name | Step-by-Step Technical Procedure | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **P2-01** | **Argon2id Integration** | 1. Add the `argon2` crate. <br> 2. Implement a key-stretching function that uses a 16-byte salt. <br> 3. Map the Argon2 output directly to the engine's LCG seed. | Resistance against high-speed GPU brute-force attacks. |
| **P2-02** | **File Header Serialization** | 1. Define the binary layout: <br>     a. `[0..4]` Magic Bytes (`CRYP`). <br>     b. `[4..6]` Version. <br>     c. `[6..22]` Salt. <br>     d. `[22..34]` Nonce. <br> 2. Create methods to write/read this header to a byte stream. | A standardized `.cryp` file format that stores session metadata. |
| **P2-03** | **Encrypt-then-MAC (HMAC)** | 1. Add the `hmac` and `sha2` crates. <br> 2. After encryption, calculate the HMAC-SHA256 over the entire file (header + ciphertext). <br> 3. Append the 32-byte MAC to the very end of the file. | Complete protection against unauthorized data tampering. |
| **P2-04** | **Buffered Stream I/O** | 1. Use `std::io::BufReader` to read the input file in 4KB chunks. <br> 2. Process chunks through the `ChainedEngine`. <br> 3. Write results to a new `.cryp` file using `BufWriter`. | High-performance processing of large binary files (PDFs, images). |

-----

### Phase 3: Interface & UX (The CLI and GUI)

This phase transforms the library into a usable application for non-developers.

| ID | Task Name | Step-by-Step Technical Procedure | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **P3-01** | **Command-Line Interface** | 1. Add the `clap` crate. <br> 2. Define arguments: `-e` (encrypt), `-d` (decrypt), `-f` (file path), and `-p` (passkey). <br> 3. Implement subcommands for "Text Mode" vs "File Mode." | A terminal-based tool for power users and automation. |
| **P3-02** | **Native GUI Layout** | 1. Set up a **Slint** or **Iced** project. <br> 2. Create a "Drag-and-Drop" zone for files. <br> 3. Add a password input field with a "strength meter" visualization. | A professional, modern interface for the desktop app. |
| **P3-03** | **Error Handling & Feedback** | 1. Create a custom `CryptionError` enum (InvalidMAC, WrongPassword, FileInaccessible). <br> 2. Implement a progress bar that updates based on the byte stream position. | A robust user experience with clear, actionable error messages. |

-----

### Phase 4: QA, Auditing & Final Release

The final polish to ensure the project is ready for professional portfolio.

| ID | Task Name | Step-by-Step Technical Procedure | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **P4-01** | **Avalanche Effect Testing** | 1. Write a test to encrypt a 100-byte file. <br> 2. Change exactly 1 bit in the key and encrypt again. <br> 3. Calculate the **Hamming Distance**; ensure \>50% of bits changed. | Empirical proof that the "Chained" logic is cryptographically sound. |
| **P4-02** | **Integrity Stress Test** | 1. Encrypt a file to `.cryp`. <br> 2. Use a hex editor to change one byte in the ciphertext. <br> 3. Attempt decryption; verify the system catches the HMAC failure. | Verification that the "Tamper Resistance" layer is working. |
| **P4-03** | **Documentation & Release** | 1. Finalize `DESIGN.md` and `ALGORITHM.md` with the Rust findings. <br> 2. Create a GitHub Release. <br> 3. Include compiled binaries for Windows/Linux. | A complete, high-impact project for resume and portfolio. |
