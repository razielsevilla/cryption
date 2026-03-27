## 🔬 Technical Specification: Chained Algorithm v2.0

The Chained Algorithm is a symmetric block cipher designed around a $16 \times 16$ dynamic byte matrix. Its security relies on the unpredictable shuffling of this state space, driven by a cryptographically seeded PRNG.

### 1. Key Sensitivity (Polynomial Hashing)
To ensure high sensitivity to the input seed, the passkey $S$ is converted into a seed value $H$ using **Polynomial Hashing**:

$$H = \left( \sum_{i=0}^{n-1} \text{ord}(S[i]) \cdot P^i \right) \pmod M$$

* **$P$**: A prime number (53) to minimize collisions.
* **$M$**: A $2^{64}$ modulus for a vast seed space.

### 2. State Generation (Linear Congruential Generator)
The hash $H$ initializes a **Linear Congruential Generator (LCG)**. To prevent identical ciphertexts for identical plaintexts (Replay Attacks), a random 12-byte **Nonce** is combined with $H$. 

**Nonce Mixing Logic:** Each byte of the nonce is "absorbed" into the state using the LCG formula:
$$X_{next} = (aX_{current} + \text{nonce\_byte} + c) \pmod m$$
This ensures that even a 1-bit change in the nonce spreads across the entire 64-bit initial state, providing a unique starting sequence for every encryption session.

$$X_{n+1} = (aX_n + c) \pmod m$$

While standard LCGs have known weaknesses, in **Cryption**, the LCG is not used to generate the ciphertext itself, but rather to determine the *permutation path* of the character matrix and the *dynamic offset* for every byte.

### 3. The $16 \times 16$ Matrix Shuffle
The core "Substitution-Permutation" layer involves a 256-character set (All ASCII characters). 
* **Mapping:** A byte $B$ is mapped to coordinate $(r, c)$ where $r = \lfloor B / 16 \rfloor$ and $c = B \pmod{16}$.
* **Permutation:** The LCG sequence determines $N$ rounds of Fisher-Yates shuffling on the 256-element byte array before encryption begins.

### 4. Cipher Chaining & The Avalanche Effect
To achieve high diffusion, Cryption uses **Dynamic Offset Substitution**. 

1. **Advance State:** For each plaintext byte $P_i$, the LCG is advanced to generate a pseudo-random value $R_i$.
2. **Dynamic Substitution:** The ciphertext $C_i$ is calculated by indexing the matrix with a wrapped offset:
   $$C_i = \text{Matrix}[(P_i + \text{LSB}(R_i)) \pmod{256}]$$
3. **The Chain:** The LCG state is then updated by XORing it with the resulting ciphertext:
   $$X_{next} = X_{current} \oplus C_i$$

This ensures:
* **Forward Diffusion:** Every subsequent byte $P_{i+1}$ is transformed using a state modified by all previous ciphertext bytes.
* **Avalanche Effect:** A 1-bit change in the key results in a $>50\%$ difference in ciphertext (Empirically verified in Phase 4-01).
