# Partially Homomorphic Encryption (PHE) Prototype: Encrypted Cloud DB

A high-performance, secure, and zero-knowledge cloud database prototype built in **Rust** using a custom **Paillier Cryptosystem** implemented completely from scratch.

This project simulates a secure cloud database architecture where a client outsources product pricing storage to an untrusted cloud provider. Thanks to the homomorphic properties of the Paillier Cryptosystem, the cloud database can perform secure aggregated calculations (such as `SUM`) on the encrypted values without ever decrypting them, preserving absolute user privacy.

---

## 🏗️ Architecture & Security Model

```
           +-----------------------------------------------+
           |              Trusted Client CLI               |
           |  1. Generate public key (n, g) & private key   |
           |  2. Read product prices from CSV file         |
           |  3. Encrypt prices locally                    |
           |  4. Decrypt aggregate result from Server      |
           +-----------------------+-----------------------+
                                   |
                       HTTP REST   |  (Public key & Ciphertexts)
                       API Calls   |  (No plaintexts ever transmitted)
                                   v
           +-----------------------------------------------+
           |              Untrusted Cloud API              |
           |  - Axum Web Server Endpoint Storage           |
           |  - Stores ONLY encrypted strings in SQLite    |
           |  - Computes Encrypted SUM securely:           |
           |    c_sum = Product(c_i) mod n^2               |
           +-----------------------+-----------------------+
                                   |
                                   v
                         +-------------------+
                         | SQLite Database   |
                         | (Zero Knowledge)  |
                         +-------------------+
```

1. **Client (Trusted CLI):** Generates the Paillier key pair. It reads 1,000 product prices, encrypts them using the public key, uploads the encrypted values to the cloud database, and keeps the private key strictly local. After the cloud computes the secure sum, the client fetches the ciphertext, decrypts it, and verifies correctness.
2. **Server (Untrusted Axum Web Server):** Stores only high-entropy ciphertext strings in SQLite. The server is completely blind to individual product prices. When a `SUM` is requested, it performs the homomorphic addition by **multiplying** all stored ciphertexts modulo $n^2$:
   $$C_{\text{sum}} = \prod_{i=1}^{k} C_i \pmod{n^2}$$
   It returns the aggregated ciphertext back to the client.

---

## 📦 Workspace Structure

The project is designed as a modular **Cargo Workspace** for complete decoupling of mathematics from network and storage layers:

* **`paillier-crypto` (Library Crate):** The cryptography core implemented from scratch.
  * Probabilistic **Miller-Rabin** primality test.
  * Large probable prime generator for customizable security sizes.
  * **Extended Euclidean Algorithm** for modular multiplicative inverse.
  * Full Paillier core (Keypair generation, Encryption, Decryption, Homomorphic Addition).
* **`cloud-server` (Binary Crate):** Lightweight web API using **Axum** and **rusqlite**.
  * Stores ciphertext records in a local `cloud_db.sqlite` file.
  * Performs zero-knowledge homomorphic products over ciphertexts.
* **`client-cli` (Binary Crate):** Local driver and benchmarking harness.
  * Generates 1,000 synthetic products (`data/product_prices.csv`).
  * Runs a full automated benchmarking loop comparing different key sizes ($256$, $512$, $1024$, $2048$ bits).
* **`scripts/hacker_mode_demo.py`:** Interactive hacker demonstration.
  * Simulates an attacker attempting data dumping and tampering to prove the system's zero-knowledge security.

---

## 🧮 Paillier Cryptosystem Mathematics

Implemented fully from scratch using the `num-bigint` arbitrary-precision crate:

### 1. Key Generation
1. Choose two large random primes $p$ and $q$ of similar bit length.
2. Compute $n = p \times q$ and $g = n + 1$.
3. Compute $\lambda = \text{lcm}(p-1, q-1) = \frac{(p-1)(q-1)}{\gcd(p-1, q-1)}$.
4. Compute $\mu = \lambda^{-1} \pmod n$ (using the Extended Euclidean Algorithm).
5. **Public Key:** $(n, g)$  
6. **Private Key:** $(\lambda, \mu)$

### 2. Encryption
Given a message $0 \le m < n$:
1. Choose a random integer $r$ in range $[1, n-1]$.
2. Compute the ciphertext $c = (g^m \cdot r^n) \pmod{n^2}$.

### 3. Decryption
Given a ciphertext $0 < c < n^2$:
1. Compute $u = c^\lambda \pmod{n^2}$.
2. Compute the L-function: $L(u) = \frac{u - 1}{n}$.
3. Recover the plaintext message: $m = (L(u) \times \mu) \pmod n$.

### 4. Homomorphic Properties
Given two ciphertexts $c_1$ and $c_2$ corresponding to messages $m_1$ and $m_2$:
$$c_1 \cdot c_2 = (g^{m_1} \cdot r_1^n)(g^{m_2} \cdot r_2^n) \equiv g^{m_1 + m_2} \cdot (r_1 r_2)^n \pmod{n^2}$$
Decryption of the product of ciphertexts results in the sum of plaintexts:
$$D(c_1 \cdot c_2 \bmod n^2) = m_1 + m_2 \pmod n$$

---

## 🚀 Execution & Benchmarks

### Prerequisites
* [Rust](https://www.rust-lang.org/tools/install) (1.74+)

### 1. Run the Cloud Server
Start the Axum Web Server:
```bash
cargo run --release -p cloud-server
```
The server will initialize the SQLite database `cloud_db.sqlite` and begin listening on `http://127.0.0.1:8000`.

### 2. Run the Benchmarks
In a separate terminal, launch the client runner:
```bash
cargo run --release -p client-cli
```

### 3. Run the Hacker Mode Demo
To simulate an attack on the database and demonstrate its security, run the interactive Python script:
```bash
python scripts/hacker_mode_demo.py
```

---

## 📊 Performance Benchmarks (1,000 Records)

Tested on a local machine in `--release` mode. The client encrypts 1,000 records, uploads them, requests the server to sum them, decrypts the result, and verifies correctness.

| Key Size (bits) | Keygen (ms) | Encrypt 1000 (ms) | Plaintext Sum (ms) | Homomorphic Sum (ms) | Verification |
|-----------------|-------------|-------------------|--------------------|----------------------|--------------|
| 256             | 5.19        | 100.66            | 0.0005             | 0.4852               | PASSED       |
| 512             | 12.33       | 428.39            | 0.0005             | 0.9600               | PASSED       |
| 1024            | 30.59       | 2525.03           | 0.0005             | 2.8693               | PASSED       |
| 2048 (NIST)     | 469.73      | 19479.96          | 0.0005             | 9.4058               | PASSED       |

### 🔍 Analysis of Results
1. **Blistering Summation Speeds:** Performing a secure sum of 1,000 encrypted numbers on the cloud server takes **only 9.41 ms** under a NIST-standard 2048-bit key size! This is incredibly fast and demonstrates the extreme efficiency of the homomorphic multiplication property compared to heavy cryptographic operations.
2. **The Encryption Bottleneck:** Encryption is the most compute-heavy phase. Encrypting 1,000 prices under 2048-bit keys takes 19.48 seconds due to modular exponentiation of massive numbers. However, because this is performed client-side and can be done incrementally or in parallel, it is perfectly practical.
3. **Security vs. Speed Trade-off:** As key size doubles, encryption time increases roughly quadratically. 2048-bit keys provide robust, production-grade security, whereas smaller bit-sizes (like 256 or 512 bits) are ideal for ultra-fast, low-power IoT applications but do not offer strong cryptographic security.
