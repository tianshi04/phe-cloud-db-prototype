use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

/// Probabilistic Miller-Rabin primality test.
/// Returns true if `n` is probably prime, and false if it is definitely composite.
/// `k` represents the number of testing rounds (standard is 40).
pub fn is_prime(n: &BigUint, k: usize) -> bool {
    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    if *n <= one {
        return false;
    }
    if *n == two || *n == three {
        return true;
    }
    if n % &two == zero {
        return false;
    }

    // Write n - 1 as 2^s * d by factoring out powers of 2 from n - 1
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u64;
    while &d % &two == zero {
        d /= &two;
        s += 1;
    }

    let mut rng = thread_rng();

    for _ in 0..k {
        // Choose random a in [2, n - 2]
        let low = two.clone();
        let high = n - &two;
        if high <= low {
            // For tiny n values
            continue;
        }
        let a = rng.gen_biguint_range(&low, &high);

        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }

        let mut composite = true;
        for _ in 0..(s - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
        }

        if composite {
            return false;
        }
    }

    true
}

/// Generates a random probable prime of the specified bit length.
pub fn generate_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        // Generate random biguint of specified bit size
        let mut p: BigUint = rng.gen_biguint(bits as u64);

        // Ensure the top bit is set (so it has the correct bit length)
        // and the bottom bit is set (so it's odd)
        p.set_bit((bits - 1) as u64, true);
        p.set_bit(0, true);

        if is_prime(&p, 40) {
            return p;
        }
    }
}
