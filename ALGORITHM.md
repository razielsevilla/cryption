## 🔬 Technical Specification: Chained Algorithm v2.0

The Chained Algorithm is a symmetric block cipher designed around a $10 \times 10$ dynamic character matrix. Its security relies on the unpredictable shuffling of this state space, driven by a cryptographically seeded PRNG.

### 1. Key Sensitivity (Polynomial Hashing)
To ensure that even a single character change in the user's passkey results in a vastly different initial state, the algorithm uses **Polynomial Rolling Hashing**. The passkey $S$ of length $n$ is converted into a seed value $H$ using the formula:

$$H = \left( \sum_{i=0}^{n-1} \text{ord}(S[i]) \cdot P^i \right) \pmod M$$

* **$P$**: A large prime number (e.g., 31 or 53) to minimize collisions.
* **$M$**: A large modulus (typically $2^{64}$) to provide a wide seed space for the LCG.

### 2. State Generation (Linear Congruential Generator)
The resulting hash $H$ initializes a **Linear Congruential Generator (LCG)**. This LCG produces the pseudo-random sequence required to shuffle the $10 \times 10$ matrix:

$$X_{n+1} = (aX_n + c) \pmod m$$

While standard LCGs have known weaknesses, in **Cryption**, the LCG is not used to generate the ciphertext itself, but rather to determine the *permutation path* of the character matrix for every block.

### 3. The $10 \times 10$ Matrix Shuffle
The core "Substitution-Permutation" layer involves a 100-character set (Alpha-numeric + Special characters). 
1.  **Initial State:** The matrix is populated with a standard character set.
2.  **Shuffling:** Using the LCG sequence, the algorithm performs $N$ rounds of Fisher-Yates shuffling on the matrix.
3.  **Mapping:** Each plaintext character is located in the matrix and replaced based on a coordinate-shift logic determined by the current LCG state.

### 4. Cipher Chaining & The Avalanche Effect
To prevent identical plaintext blocks from producing identical ciphertext (a weakness of basic ECB mode), Cryption implements **Cipher Chaining**. 

Each encrypted character $C_i$ is XORed back into the LCG's internal state before processing the next character $P_{i+1}$. This ensures that:
* **Forward Diffusion:** An error or change in character 1 ripples through the entire remaining ciphertext.
* **Avalanche Effect:** A 1-bit change in the key or the first character of plaintext results in a $>50\%$ change in the resulting ciphertext bits.
