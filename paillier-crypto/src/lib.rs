pub mod primes;

use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::{One, Zero};

use std::fmt;

/// An error that can occur in Paillier operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The plaintext message is invalid (must be 0 <= m < n).
    InvalidPlaintext,
    /// The ciphertext is invalid (must be 0 < c < n^2).
    InvalidCiphertext,
    /// Decryption experienced underflow.
    Underflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPlaintext => write!(f, "Invalid plaintext message: must be 0 <= m < n"),
            Error::InvalidCiphertext => write!(f, "Invalid ciphertext: must be 0 < c < n^2"),
            Error::Underflow => write!(f, "Decryption underflow: intermediate value u < 1"),
        }
    }
}

impl std::error::Error for Error {}

/// A Paillier Public Key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    /// The modulus n = p * q
    n: BigUint,
    /// The generator g (standard is n + 1)
    g: BigUint,
}

impl PublicKey {
    /// Creates a new Paillier public key with modulus `n` and generator `g`.
    pub fn new(n: BigUint, g: BigUint) -> Self {
        Self { n, g }
    }

    /// Returns a reference to the modulus `n`.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Returns a reference to the generator `g`.
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// Encrypts a plaintext message `m` (where 0 <= m < n) using this public key.
    /// Returns the ciphertext.
    ///
    /// # Errors
    /// - Returns `Error::InvalidPlaintext` if the message `m` is greater than or equal to `n`.
    pub fn encrypt(&self, m: &BigUint) -> Result<BigUint, Error> {
        if m >= &self.n {
            return Err(Error::InvalidPlaintext);
        }

        let n_sq = &self.n * &self.n;

        // Generate random r in [1, n-1] coprime to n
        let mut rng = rand::thread_rng();
        let r = loop {
            let r = rng.gen_biguint_range(&BigUint::one(), &self.n);
            if gcd(r.clone(), self.n.clone()) == BigUint::one() {
                break r;
            }
        };

        // c = (g^m * r^n) mod n^2
        // Optimization: if g = n + 1, g^m mod n^2 = (1 + m*n) mod n^2 (Binomial Theorem)
        let g_m = if self.g == &self.n + BigUint::one() {
            (BigUint::one() + m * &self.n) % &n_sq
        } else {
            self.g.modpow(m, &n_sq)
        };
        let r_n = r.modpow(&self.n, &n_sq);

        Ok((g_m * r_n) % &n_sq)
    }
}

/// A Paillier Private Key.
///
/// # Security Considerations
/// - **Timing Side-Channels:** The modular exponentiation (`modpow`) implemented in `num-bigint`
///   is not guaranteed to be constant-time. For cryptographic production deployments, a constant-time
///   exponentiation implementation should be used to protect against timing attacks.
/// - **Ciphertext Authenticity:** Standard Paillier is homomorphic and malleable, meaning ciphertexts
///   can be manipulated by an attacker (e.g. multiplied by a scalar to multiply the underlying plaintext)
///   without detection. In a production environment, you should wrap the ciphertexts with authenticators
///   (such as a MAC, digital signature, AEAD wrapper, or Zero-Knowledge proof of correctness).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivateKey {
    /// lambda = lcm(p-1, q-1)
    lambda: BigUint,
    /// mu = L(g^lambda mod n^2)^-1 mod n
    /// When g = n + 1, this simplifies to lambda^-1 mod n.
    mu: BigUint,
    /// The modulus n = p * q
    n: BigUint,
}

impl PrivateKey {
    /// Creates a new Paillier private key with `lambda`, `mu`, and modulus `n`.
    pub fn new(lambda: BigUint, mu: BigUint, n: BigUint) -> Self {
        Self { lambda, mu, n }
    }

    /// Returns a reference to lambda.
    pub fn lambda(&self) -> &BigUint {
        &self.lambda
    }

    /// Returns a reference to mu.
    pub fn mu(&self) -> &BigUint {
        &self.mu
    }

    /// Returns a reference to the modulus `n`.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Decrypts a ciphertext `c` (where 0 < c < n^2) using this private key.
    /// Returns the decrypted plaintext message.
    ///
    /// # Errors
    /// - Returns `Error::InvalidCiphertext` if the ciphertext `c` is invalid (c == 0 or c >= n^2).
    /// - Returns `Error::Underflow` if intermediate calculation `u` is less than 1.
    pub fn decrypt(&self, c: &BigUint) -> Result<BigUint, Error> {
        let n_sq = &self.n * &self.n;

        // Validate ciphertext: must be 0 < c < n^2
        if c.is_zero() || c >= &n_sq {
            return Err(Error::InvalidCiphertext);
        }

        // u = c^lambda mod n^2
        let u = c.modpow(&self.lambda, &n_sq);

        // L(u) = (u - 1) / n
        if u < BigUint::one() {
            return Err(Error::Underflow);
        }
        let l_u = (&u - BigUint::one()) / &self.n;

        // m = (L(u) * mu) mod n
        Ok((l_u * &self.mu) % &self.n)
    }
}

/// Extended Euclidean Algorithm helper.
/// Returns (g, x, y) such that a*x + b*y = g.
fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = egcd(&(b % a), a);
        (g, y - (b / a) * &x, x)
    }
}

/// Computes the modular inverse of `a` modulo `m`.
/// Returns `None` if no inverse exists (i.e. if gcd(a, m) != 1).
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_signed = BigInt::from_biguint(Sign::Plus, a.clone());
    let m_signed = BigInt::from_biguint(Sign::Plus, m.clone());

    let (g, x, _) = egcd(&a_signed, &m_signed);
    if g == BigInt::one() {
        let res = (&x % &m_signed + &m_signed) % &m_signed;
        res.to_biguint()
    } else {
        None
    }
}

/// Computes the Greatest Common Divisor (GCD) of `a` and `b`.
fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
    while !b.is_zero() {
        let r = a % &b;
        a = b;
        b = r;
    }
    a
}

/// Generates a Paillier key pair (public key, private key) of the specified bit length.
pub fn generate_keys(bits: usize) -> (PublicKey, PrivateKey) {
    let p_bits = bits / 2;
    let q_bits = bits - p_bits;

    loop {
        let p = primes::generate_prime(p_bits);
        let q = primes::generate_prime(q_bits);

        if p == q {
            continue;
        }

        let n = &p * &q;

        let p_minus_1 = &p - BigUint::one();
        let q_minus_1 = &q - BigUint::one();

        // lambda = lcm(p-1, q-1)
        let g_cd = gcd(p_minus_1.clone(), q_minus_1.clone());
        let lambda = (&p_minus_1 * &q_minus_1) / g_cd;

        let g = &n + BigUint::one();

        // For g = n + 1, mu = L(g^lambda mod n^2)^-1 mod n simplifies to lambda^-1 mod n
        if let Some(mu) = mod_inverse(&lambda, &n) {
            let pk = PublicKey::new(n.clone(), g);
            let sk = PrivateKey::new(lambda, mu, n.clone());
            return (pk, sk);
        }
    }
}

/// Combines multiple ciphertexts to represent their sum under the Paillier homomorphic addition.
/// Done by multiplying the ciphertexts modulo n^2.
pub fn homomorphic_sum(ciphertexts: &[BigUint], n: &BigUint) -> BigUint {
    let n_sq = n * n;
    let mut sum_cipher = BigUint::one();
    for c in ciphertexts {
        sum_cipher = (sum_cipher * c) % &n_sq;
    }
    sum_cipher
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{Zero, One};

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(BigUint::from(54u32), BigUint::from(24u32)), BigUint::from(6u32));
        assert_eq!(gcd(BigUint::from(101u32), BigUint::from(103u32)), BigUint::one());
        assert_eq!(gcd(BigUint::zero(), BigUint::from(5u32)), BigUint::from(5u32));
    }

    #[test]
    fn test_mod_inverse() {
        // 3^-1 mod 11 = 4
        assert_eq!(mod_inverse(&BigUint::from(3u32), &BigUint::from(11u32)), Some(BigUint::from(4u32)));
        // 6^-1 mod 9 doesn't exist
        assert_eq!(mod_inverse(&BigUint::from(6u32), &BigUint::from(9u32)), None);
        // 1^-1 mod 5 = 1
        assert_eq!(mod_inverse(&BigUint::one(), &BigUint::from(5u32)), Some(BigUint::one()));
    }

    #[test]
    fn test_paillier_roundtrip_and_homomorphic_sum() {
        // Generate a 128-bit key pair (small for fast test execution)
        let (pk, sk) = generate_keys(128);

        let m1 = BigUint::from(42u32);
        let m2 = BigUint::from(100u32);
        let m3 = BigUint::from(7u32);

        // Test basic encrypt/decrypt
        let c1 = pk.encrypt(&m1).unwrap();
        let c2 = pk.encrypt(&m2).unwrap();
        let c3 = pk.encrypt(&m3).unwrap();

        let d1 = sk.decrypt(&c1).unwrap();
        let d2 = sk.decrypt(&c2).unwrap();
        let d3 = sk.decrypt(&c3).unwrap();

        assert_eq!(d1, m1);
        assert_eq!(d2, m2);
        assert_eq!(d3, m3);

        // Test homomorphic summation
        let ciphertexts = vec![c1, c2, c3];
        let encrypted_sum = homomorphic_sum(&ciphertexts, pk.n());
        let decrypted_sum = sk.decrypt(&encrypted_sum).unwrap();

        let expected_sum = &m1 + &m2 + &m3;
        assert_eq!(decrypted_sum, expected_sum);
    }

    #[test]
    fn test_paillier_optimization_equivalence() {
        let (pk, sk) = generate_keys(128);
        let m = BigUint::from(12345u32);

        // Verify that the optimized g^m mod n^2 formula (1 + m*n) matches the standard modpow for g = n + 1
        let n_sq = pk.n() * pk.n();
        let g_m_opt = (BigUint::one() + &m * pk.n()) % &n_sq;
        let g_m_std = pk.g().modpow(&m, &n_sq);
        assert_eq!(g_m_opt, g_m_std);

        // Verify that encrypt/decrypt roundtrip still functions correctly
        let c = pk.encrypt(&m).unwrap();
        assert_eq!(sk.decrypt(&c).unwrap(), m);
    }

    #[test]
    fn test_paillier_encrypt_validation_too_large() {
        let (pk, _sk) = generate_keys(128);
        let invalid_m = pk.n() + BigUint::one();
        assert_eq!(pk.encrypt(&invalid_m), Err(Error::InvalidPlaintext));
    }

    #[test]
    fn test_paillier_decrypt_validation_zero() {
        let (_pk, sk) = generate_keys(128);
        let invalid_c = BigUint::zero();
        assert_eq!(sk.decrypt(&invalid_c), Err(Error::InvalidCiphertext));
    }

    #[test]
    fn test_paillier_decrypt_validation_too_large() {
        let (pk, sk) = generate_keys(128);
        let n_sq = pk.n() * pk.n();
        assert_eq!(sk.decrypt(&n_sq), Err(Error::InvalidCiphertext));
    }
}
