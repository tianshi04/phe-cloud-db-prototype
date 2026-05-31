/**
 * SHADOWDB // ZK-PHE Crypto Web Worker
 * Pure ES6+ JavaScript implementation of Paillier Cryptosystem using BigInt
 * Running in a background thread to prevent blocking the UI.
 */

// ==========================================
// 1. MATHEMATICAL BIGINT UTILITIES
// ==========================================

/**
 * Fast Modular Exponentiation: (base^exp) % mod
 */
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    let exp = exponent;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exp = exp >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}

/**
 * Greatest Common Divisor (GCD)
 */
function gcd(a, b) {
    while (b !== 0n) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

/**
 * Extended Euclidean Algorithm
 * Returns [g, x, y] such that a*x + b*y = g
 */
function egcd(a, b) {
    if (a === 0n) {
        return [b, 0n, 1n];
    }
    let [g, x, y] = egcd(b % a, a);
    return [g, y - (b / a) * x, x];
}

/**
 * Modular Multiplicative Inverse: a^-1 mod m
 */
function modInverse(a, m) {
    let [g, x, y] = egcd(a, m);
    if (g !== 1n) {
        throw new Error("Modular inverse does not exist");
    }
    return (x % m + m) % m;
}

/**
 * Generates a random BigInt in range [min, max]
 */
function randomBigIntRange(min, max) {
    const range = max - min;
    const bitLength = range.toString(2).length;
    const byteLength = Math.ceil(bitLength / 8);
    
    while (true) {
        const bytes = new Uint8Array(byteLength);
        self.crypto.getRandomValues(bytes);
        let randVal = 0n;
        for (let i = 0; i < byteLength; i++) {
            randVal = (randVal << 8n) + BigInt(bytes[i]);
        }
        
        // Truncate to bit length to prevent massive overshoots
        const excessBits = (byteLength * 8) - bitLength;
        randVal = randVal >> BigInt(excessBits);
        
        const val = min + randVal;
        if (val <= max) {
            return val;
        }
    }
}

/**
 * Generates a random BigInt of exact bit length
 */
function randomBigIntBits(bits) {
    const byteLength = Math.ceil(bits / 8);
    const bytes = new Uint8Array(byteLength);
    self.crypto.getRandomValues(bytes);
    
    let val = 0n;
    for (let i = 0; i < byteLength; i++) {
        val = (val << 8n) + BigInt(bytes[i]);
    }
    
    // Ensure exact bit length and odd number
    const mask = (1n << BigInt(bits)) - 1n;
    val = val & mask;
    val = val | (1n << BigInt(bits - 1)); // Set top bit
    val = val | 1n; // Set bottom bit to ensure odd
    
    return val;
}

/**
 * Miller-Rabin Primality Test
 */
function isPrime(n, k = 15) {
    if (n === 2n || n === 3n) return true;
    if (n < 2n || n % 2n === 0n) return false;
    
    // Write n - 1 as 2^s * d
    let d = n - 1n;
    let s = 0n;
    while (d % 2n === 0n) {
        d /= 2n;
        s++;
    }
    
    // Witness loop
    witnessLoop: for (let i = 0; i < k; i++) {
        let a = randomBigIntRange(2n, n - 2n);
        let x = modPow(a, d, n);
        
        if (x === 1n || x === n - 1n) continue;
        
        for (let r = 0n; r < s - 1n; r++) {
            x = (x * x) % n;
            if (x === n - 1n) continue witnessLoop;
        }
        return false;
    }
    return true;
}

/**
 * Generates a random prime of specified bit length
 */
function generatePrime(bits) {
    while (true) {
        let p = randomBigIntBits(bits);
        if (isPrime(p)) {
            return p;
        }
    }
}

/**
 * Generates a random BigInt r in [1, n-1] coprime to n
 */
function generateRandomCoprime(n) {
    while (true) {
        let r = randomBigIntRange(1n, n - 1n);
        if (gcd(r, n) === 1n) {
            return r;
        }
    }
}


// ==========================================
// 2. PAILLIER CRYPTOSYSTEM CLASS
// ==========================================

class Paillier {
    /**
     * Generates a key pair (Public, Private)
     */
    static generateKeys(bits) {
        const pBits = Math.floor(bits / 2);
        const qBits = bits - pBits;
        
        let p, q;
        while (true) {
            p = generatePrime(pBits);
            q = generatePrime(qBits);
            if (p !== q) break;
        }
        
        const n = p * q;
        const pMinus1 = p - 1n;
        const qMinus1 = q - 1n;
        
        // lambda = lcm(p-1, q-1) = ((p-1)*(q-1)) / gcd(p-1, q-1)
        const gcdVal = gcd(pMinus1, qMinus1);
        const lambda = (pMinus1 * qMinus1) / gcdVal;
        
        const g = n + 1n;
        
        // For g = n + 1, mu = lambda^-1 mod n
        let mu;
        try {
            mu = modInverse(lambda, n);
        } catch (e) {
            // Recalculate if inverse doesn't exist (extremely rare for true primes)
            return Paillier.generateKeys(bits);
        }
        
        return {
            publicKey: {
                n: n.toString(),
                g: g.toString()
            },
            privateKey: {
                lambda: lambda.toString(),
                mu: mu.toString(),
                n: n.toString()
            }
        };
    }
    
    /**
     * Encrypt a plaintext message m (BigInt or Number) using Public Key n
     * Returns encrypted ciphertext and visualizer details
     */
    static encrypt(m, pubKeyN) {
        const n = BigInt(pubKeyN);
        const mBI = BigInt(m);
        
        if (mBI >= n) {
            throw new Error("Plaintext message too large (must be 0 <= m < n)");
        }
        
        const nSq = n * n;
        const g = n + 1n; // standard generator
        const r = generateRandomCoprime(n);
        
        // c = (g^m * r^n) mod n^2
        // Since g = n + 1, g^m mod n^2 = (1 + m*n) mod n^2 (Binomial Theorem optimization)
        const g_m = (1n + mBI * n) % nSq;
        const r_n = modPow(r, n, nSq);
        const ciphertext = (g_m * r_n) % nSq;
        
        return {
            ciphertext: ciphertext.toString(),
            // Explainer details
            visData: {
                m: mBI.toString(),
                r: r.toString(),
                gn: g_m.toString(),
                rn: r_n.toString(),
                c: ciphertext.toString()
            }
        };
    }
    
    /**
     * Decrypt a ciphertext c (BigInt or String) using Private Key
     */
    static decrypt(c, privKey) {
        const n = BigInt(privKey.n);
        const lambda = BigInt(privKey.lambda);
        const mu = BigInt(privKey.mu);
        const cBI = BigInt(c);
        const nSq = n * n;
        
        if (cBI <= 0n || cBI >= nSq) {
            throw new Error("Invalid ciphertext (must be 0 < c < n^2)");
        }
        
        // u = c^lambda mod n^2
        const u = modPow(cBI, lambda, nSq);
        
        // L(u) = (u - 1) / n
        const l_u = (u - 1n) / n;
        
        // m = (L(u) * mu) mod n
        const m = (l_u * mu) % n;
        
        return m.toString();
    }
}


// ==========================================
// 3. WEB WORKER REQUEST DISPATCHER
// ==========================================

self.onmessage = function(e) {
    const { requestId, action, payload } = e.data;
    try {
        let result;
        if (action === 'generate_keys') {
            result = Paillier.generateKeys(payload.bits);
            self.postMessage({ requestId, success: true, data: result });
        } else if (action === 'encrypt_single') {
            result = Paillier.encrypt(payload.price, payload.pubKeyN);
            self.postMessage({ requestId, success: true, data: result });
        } else if (action === 'decrypt_single') {
            result = Paillier.decrypt(payload.ciphertext, payload.privateKey);
            self.postMessage({ requestId, success: true, data: result });
        } else if (action === 'encrypt_batch') {
            const products = payload.products;
            const pubKeyN = payload.pubKeyN;
            const batchProducts = [];
            const localVisStoreTemp = {};
            const total = products.length;
            
            const progressStep = Math.max(1, Math.floor(total / 50));
            
            for (let i = 0; i < total; i++) {
                const p = products[i];
                const enc = Paillier.encrypt(p.price, pubKeyN);
                batchProducts.push({
                    name: p.name,
                    encrypted_price: enc.ciphertext
                });
                localVisStoreTemp[p.name] = enc.visData;
                
                if (i % progressStep === 0 || i === total - 1) {
                    const percent = Math.round(((i + 1) / total) * 100);
                    self.postMessage({
                        requestId,
                        type: 'progress',
                        percent,
                        current: i + 1,
                        total
                    });
                }
            }
            self.postMessage({ 
                requestId, 
                success: true, 
                data: { products: batchProducts, localVisStore: localVisStoreTemp } 
            });
        } else if (action === 'decrypt_batch') {
            const ciphertexts = payload.ciphertexts;
            const privateKey = payload.privateKey;
            const decryptedValues = [];
            
            for (let i = 0; i < ciphertexts.length; i++) {
                const dec = Paillier.decrypt(ciphertexts[i], privateKey);
                decryptedValues.push(dec);
            }
            
            self.postMessage({ requestId, success: true, data: decryptedValues });
        } else {
            throw new Error(`Unknown action: ${action}`);
        }
    } catch (err) {
        self.postMessage({ requestId, success: false, error: err.message });
    }
};
