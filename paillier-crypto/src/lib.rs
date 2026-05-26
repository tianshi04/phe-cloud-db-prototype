pub mod primes;

use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::{One, Zero};

/// A Paillier Public Key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    /// The modulus n = p * q
    pub n: BigUint,
    /// The generator g (standard is n + 1)
    pub g: BigUint,
}

impl PublicKey {
    /// Encrypts a plaintext message `m` (where 0 <= m < n) using this public key.
    /// Returns the ciphertext.
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        let n_sq = &self.n * &self.n;

        // Generate random r in [1, n-1] coprime to n
        let mut rng = rand::thread_rng();
        let r = rng.gen_biguint_range(&BigUint::one(), &self.n);

        // c = (g^m * r^n) mod n^2
        let g_m = self.g.modpow(m, &n_sq);
        let r_n = r.modpow(&self.n, &n_sq);

        (g_m * r_n) % &n_sq
    }
}

/// A Paillier Private Key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivateKey {
    /// lambda = lcm(p-1, q-1)
    pub lambda: BigUint,
    /// mu = lambda^-1 mod n
    pub mu: BigUint,
}

impl PrivateKey {
    /// Decrypts a ciphertext `c` (where 0 < c < n^2) using this private key and the public key.
    /// Returns the decrypted plaintext message.
    pub fn decrypt(&self, c: &BigUint, pk: &PublicKey) -> BigUint {
        let n_sq = &pk.n * &pk.n;

        // u = c^lambda mod n^2
        let u = c.modpow(&self.lambda, &n_sq);

        // L(u) = (u - 1) / n
        let l_u = (&u - BigUint::one()) / &pk.n;

        // m = (L(u) * mu) mod n
        (l_u * &self.mu) % &pk.n
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

        // For g = n + 1, mu = lambda^-1 mod n
        if let Some(mu) = mod_inverse(&lambda, &n) {
            let pk = PublicKey { n: n.clone(), g };
            let sk = PrivateKey { lambda, mu };
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
        let c1 = pk.encrypt(&m1);
        let c2 = pk.encrypt(&m2);
        let c3 = pk.encrypt(&m3);

        let d1 = sk.decrypt(&c1, &pk);
        let d2 = sk.decrypt(&c2, &pk);
        let d3 = sk.decrypt(&c3, &pk);

        assert_eq!(d1, m1);
        assert_eq!(d2, m2);
        assert_eq!(d3, m3);

        // Test homomorphic summation
        let ciphertexts = vec![c1, c2, c3];
        let encrypted_sum = homomorphic_sum(&ciphertexts, &pk.n);
        let decrypted_sum = sk.decrypt(&encrypted_sum, &pk);

        let expected_sum = &m1 + &m2 + &m3;
        assert_eq!(decrypted_sum, expected_sum);
    }
}
