/**
 * SHADOWDB // ZK-PHE Client Cryptography & Control Layer
 * Pure ES6+ JavaScript implementation of Paillier Cryptosystem using BigInt
 */

// ==========================================
// 0. WEB WORKER CRYPTO INTERFACE
// ==========================================

const cryptoWorker = new Worker('/crypto-worker.js');
const pendingRequests = new Map();
let nextRequestId = 1;

cryptoWorker.onmessage = function(e) {
    const { requestId, type, success, data, error, percent, current, total } = e.data;
    const pending = pendingRequests.get(requestId);
    if (pending) {
        if (type === 'progress') {
            if (pending.onProgress) {
                pending.onProgress({ percent, current, total });
            }
            return;
        }
        pendingRequests.delete(requestId);
        if (success) {
            pending.resolve(data);
        } else {
            pending.reject(new Error(error));
        }
    }
};

function callWorker(action, payload, onProgress) {
    return new Promise((resolve, reject) => {
        const requestId = nextRequestId++;
        pendingRequests.set(requestId, { resolve, reject, onProgress });
        cryptoWorker.postMessage({ requestId, action, payload });
    });
}

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
        window.crypto.getRandomValues(bytes);
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
    window.crypto.getRandomValues(bytes);
    
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
// 3. SPA STATE & UI CONTROLLER
// ==========================================

const App = {
    // Application State
    state: {
        publicKey: null,
        privateKey: null,
        products: [],
        encryptedSum: null,
        decryptedSum: null,
        isTableDecrypted: false,
        localSum: null,
        // Stores math parameters for products encrypted client-side in the current session
        localVisStore: {},
        decryptedPrices: {} // Cache for decrypted prices to prevent blocking UI during render
    },
    
    // Initializer
    init() {
        console.log("Paillier Simulator client online.");
        this.cacheDOM();
        this.bindEvents();
        this.bindManualCalculator();
        this.initTheme();
        this.loadKeysFromStorage();
        this.checkServerStatus();
        this.fetchProducts();
    },
    
    // DOM Element Caching
    cacheDOM() {
        // Headers & Status
        this.serverStatusDot = document.getElementById("server-status-dot");
        this.btnResetDb = document.getElementById("btn-reset-db");
        this.btnThemeToggle = document.getElementById("btn-theme-toggle");
        
        // Keys Panel
        this.keySizeSelect = document.getElementById("key-size-select");
        this.btnGenerateKeys = document.getElementById("btn-generate-keys");
        this.keyInfoContainer = document.getElementById("key-info-container");
        this.noKeysAlert = document.getElementById("no-keys-alert");
        this.pubKeyN = document.getElementById("pub-key-n");
        this.privKeyLambda = document.getElementById("priv-key-lambda");
        this.privKeyMu = document.getElementById("priv-key-mu");
        this.btnExportKeys = document.getElementById("btn-export-keys");
        
        // Local sum
        this.btnCalculateLocalSum = document.getElementById("btn-calculate-local-sum");
        this.localSumResultsArea = document.getElementById("local-sum-results-area");
        this.localSumVal = document.getElementById("local-sum-val");
        
        // Products Form & CSV
        this.formAddProduct = document.getElementById("form-add-product");
        this.prodName = document.getElementById("prod-name");
        this.prodPrice = document.getElementById("prod-price");
        this.btnAddProduct = document.getElementById("btn-add-product");
        
        this.csvDropZone = document.getElementById("csv-drop-zone");
        this.csvFileInput = document.getElementById("csv-file-input");
        this.btnTriggerFile = document.getElementById("btn-trigger-file");
        this.csvProgressContainer = document.getElementById("csv-progress-container");
        this.csvProgressText = document.getElementById("csv-progress-text");
        this.csvProgressPercent = document.getElementById("csv-progress-percent");
        this.csvProgressBar = document.getElementById("csv-progress-bar");
        
        // Product List
        this.productTableBody = document.getElementById("product-table-body");
        this.productCount = document.getElementById("product-count");
        this.btnDecryptAllTable = document.getElementById("btn-decrypt-all-table");
        
        // Homomorphic Sum Panel
        this.statProductsCount = document.getElementById("stat-products-count");
        this.statKeyStatus = document.getElementById("stat-key-status");
        this.btnCalculateSum = document.getElementById("btn-calculate-sum");
        this.sumResultsArea = document.getElementById("sum-results-area");
        this.resultEncryptedSum = document.getElementById("result-encrypted-sum");
        this.btnDecryptSum = document.getElementById("btn-decrypt-sum");
        this.decryptedResultBox = document.getElementById("decrypted-result-box");
        this.decryptedSumVal = document.getElementById("decrypted-sum-val");
        this.verificationStatus = document.getElementById("verification-status");
        
        // Mathematical Visualizer
        this.visProductSelect = document.getElementById("visualizer-product-select");
        this.visDetailsArea = document.getElementById("vis-details-area");
        this.visNoData = document.getElementById("vis-no-data");
        this.visM = document.getElementById("vis-m");
        this.visR = document.getElementById("vis-r");
        this.visGN = document.getElementById("vis-gn");
        this.visRN = document.getElementById("vis-rn");
        this.visC = document.getElementById("vis-c");
        
        this.visHomoCalcArea = document.getElementById("vis-homo-calc-area");
        this.visHomoCalcExpression = document.getElementById("vis-homo-calc-expression");
    },
    
    // Bind Event Listeners
    bindEvents() {
        // Global db reset
        this.btnResetDb.addEventListener("click", () => this.resetDatabase());
        
        // Theme toggle
        if (this.btnThemeToggle) {
            this.btnThemeToggle.addEventListener("click", () => this.toggleTheme());
        }
        
        // Key pair generation
        this.btnGenerateKeys.addEventListener("click", () => this.generateKeys());
        
        // Copy to clipboard shortcuts
        this.pubKeyN.addEventListener("click", () => this.copyToClipboard(this.pubKeyN.innerText, "Public Key N"));
        this.resultEncryptedSum.addEventListener("click", () => this.copyToClipboard(this.resultEncryptedSum.innerText, "Encrypted Sum"));
        
        // Export file keys
        this.btnExportKeys.addEventListener("click", () => this.exportKeys());
        
        // Add single product
        this.formAddProduct.addEventListener("submit", (e) => {
            e.preventDefault();
            this.addSingleProduct();
        });
        
        // CSV Drag & Drop triggers
        this.btnTriggerFile.addEventListener("click", () => this.csvFileInput.click());
        this.csvFileInput.addEventListener("change", (e) => this.handleCsvFile(e.target.files[0]));
        
        this.csvDropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            this.csvDropZone.classList.add("dragover");
        });
        this.csvDropZone.addEventListener("dragleave", () => {
            this.csvDropZone.classList.remove("dragover");
        });
        this.csvDropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            this.csvDropZone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                this.handleCsvFile(e.dataTransfer.files[0]);
            }
        });
        
        // Table Decryption Toggle
        if (this.btnDecryptAllTable) {
            this.btnDecryptAllTable.addEventListener("click", () => this.toggleTableDecryption());
        }
        
        // Local sum
        if (this.btnCalculateLocalSum) {
            this.btnCalculateLocalSum.addEventListener("click", () => this.calculateLocalSum());
        }
        
        // Homomorphic sum
        this.btnCalculateSum.addEventListener("click", () => this.calculateHomomorphicSum());
        this.btnDecryptSum.addEventListener("click", () => this.decryptHomomorphicSum());
        
        // Visualizer Tabs
        document.querySelectorAll(".tab-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
                document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));
                
                btn.classList.add("active");
                document.getElementById(btn.dataset.tab).classList.add("active");
            });
        });
        
        // Visualizer Select Dropdown
        if (this.visProductSelect) {
            this.visProductSelect.addEventListener("change", (e) => this.updateStepVisualizer(e.target.value));
        }
    },
    
    // Server Health Check
    async checkServerStatus() {
        // The server is serving this web app so it is online.
        this.serverStatusDot.className = "status-dot green";
    },
    
    // Retrieve Client Keys from localStorage
    loadKeysFromStorage() {
        const storedKeys = localStorage.getItem("shadowdb_keys");
        if (storedKeys) {
            try {
                const keys = JSON.parse(storedKeys);
                this.state.publicKey = keys.publicKey;
                this.state.privateKey = keys.privateKey;
                this.renderKeys();
                this.enableSecureInputs(true);
            } catch (e) {
                console.error("Failed to parse keys from storage", e);
            }
        }
    },
    
    // Generate Keypair In-Browser
    async generateKeys() {
        const bits = parseInt(this.keySizeSelect.value);
        this.btnGenerateKeys.disabled = true;
        this.btnGenerateKeys.innerText = "ĐANG TẠO KHÓA (LOCAL)...";
        
        // Put in micro-task delay to allow DOM to render the loading state
        await new Promise(resolve => setTimeout(resolve, 50));
        
        const startTime = performance.now();
        try {
            const keys = await callWorker('generate_keys', { bits });
            const duration = (performance.now() - startTime).toFixed(1);
            console.log(`Generated ${bits}-bit keys in ${duration}ms locally.`);
            
            this.state.publicKey = keys.publicKey;
            this.state.privateKey = keys.privateKey;
            this.state.decryptedPrices = {}; // Reset decryption cache for new keys
            
            // Save locally in localStorage
            localStorage.setItem("shadowdb_keys", JSON.stringify(keys));
            
            this.renderKeys();
            this.enableSecureInputs(true);
            
            // Reset homomorphic summation display
            this.sumResultsArea.style.display = "none";
            this.decryptedResultBox.style.display = "none";
            const gaugeFill = document.getElementById("local-sum-gauge-fill");
            if (gaugeFill) {
                gaugeFill.style.strokeDashoffset = "251.2";
                gaugeFill.style.stroke = "var(--accent-coral)";
            }
            
            this.showToast(`Khởi tạo cặp khóa ${bits}-bit thành công trong ${duration}ms!`, "success");
        } catch (e) {
            console.error("Keygen failed", e);
            this.showToast("Tạo khóa thất bại. Vui lòng thử lại!", "danger");
        } finally {
            this.btnGenerateKeys.disabled = false;
            this.btnGenerateKeys.innerText = "KHỞI TẠO CẶP KHÓA MỚI";
        }
    },
    
    // Render generated keys in sidepanel
    renderKeys() {
        if (!this.state.publicKey) return;
        
        this.pubKeyN.innerText = this.state.publicKey.n;
        this.privKeyLambda.innerText = this.state.privateKey.lambda;
        this.privKeyMu.innerText = this.state.privateKey.mu;
        
        this.noKeysAlert.style.display = "none";
        this.keyInfoContainer.style.display = "flex";
        
        this.statKeyStatus.innerText = "ĐÃ UPLOAD (AUTO)";
        this.statKeyStatus.style.color = "var(--success)";
        
        // Auto-fill manual calculator key inputs
        const manualPubN = document.getElementById("manual-pub-n");
        const manualPrivLambda = document.getElementById("manual-priv-lambda");
        const manualPrivMu = document.getElementById("manual-priv-mu");
        const manualPrivN = document.getElementById("manual-priv-n");
        
        if (manualPubN && this.state.publicKey) manualPubN.value = this.state.publicKey.n;
        if (manualPrivLambda && this.state.privateKey) manualPrivLambda.value = this.state.privateKey.lambda;
        if (manualPrivMu && this.state.privateKey) manualPrivMu.value = this.state.privateKey.mu;
        if (manualPrivN && this.state.publicKey) manualPrivN.value = this.state.publicKey.n;
    },
    
    // Toggle state of inputs requiring cryptographic key
    enableSecureInputs(enabled) {
        this.btnAddProduct.disabled = !enabled;
        this.btnCalculateSum.disabled = !enabled || this.state.products.length === 0;
        if (this.btnCalculateLocalSum) {
            this.btnCalculateLocalSum.disabled = !enabled || this.state.products.length === 0;
        }
        if (this.btnDecryptAllTable) {
            this.btnDecryptAllTable.disabled = !enabled || this.state.products.length === 0;
        }
    },
    
    // Copy key string to clipboard
    copyToClipboard(text, name) {
        navigator.clipboard.writeText(text).then(() => {
            this.showToast(`Đã copy ${name} vào Clipboard!`, "success");
        }).catch(err => {
            console.error("Failed to copy", err);
        });
    },
    
    // Export key pair to a downloadable JSON file
    exportKeys() {
        if (!this.state.publicKey) return;
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
            publicKey: this.state.publicKey,
            privateKey: this.state.privateKey
        }, null, 4));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `shadowdb_paillier_keys_${this.keySizeSelect.value}bit.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    },
    
    // Fetch stored products from Cloud server
    async fetchProducts() {
        try {
            const response = await fetch("/api/products");
            if (!response.ok) throw new Error("API call failed");
            
            const products = await response.json();
            this.state.products = products;
            this.renderProductTable();
            this.updateStats();
            
            // Check server public key sync
            this.checkKeySync();
        } catch (e) {
            console.error("Failed to fetch products", e);
            // If table empty, render default error
            this.productTableBody.innerHTML = `
                <tr>
                    <td colspan="3" class="text-center text-muted py-4">
                        Lỗi kết nối đến Cloud Server. Vui lòng đảm bảo server đang chạy.
                    </td>
                </tr>
            `;
        }
    },

    async checkKeySync() {
        if (!this.state.publicKey) return;
        
        try {
            const res = await fetch("/api/public-key");
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.status === "success" && data.public_key_n) {
                const serverN = data.public_key_n;
                const clientN = this.state.publicKey.n;
                
                if (serverN !== clientN) {
                    console.warn("Key mismatch detected!");
                    this.statKeyStatus.innerText = "LỆCH KHÓA (CẦN RESET DB)";
                    this.statKeyStatus.style.color = "var(--danger)";
                    
                    // Show a non-blocking floating alert or notification banner
                    this.showKeyMismatchWarning();
                } else {
                    this.statKeyStatus.innerText = "ĐÃ UPLOAD (AUTO)";
                    this.statKeyStatus.style.color = "var(--success)";
                    this.hideKeyMismatchWarning();
                }
            } else {
                // No public key on server yet
                this.statKeyStatus.innerText = "Chưa có";
                this.statKeyStatus.style.color = "var(--text-muted)";
                this.hideKeyMismatchWarning();
            }
        } catch (e) {
            console.error("Failed to check key sync", e);
        }
    },
    
    showKeyMismatchWarning() {
        let warningDiv = document.getElementById("key-mismatch-warning");
        if (!warningDiv) {
            warningDiv = document.createElement("div");
            warningDiv.id = "key-mismatch-warning";
            warningDiv.className = "no-keys-alert";
            warningDiv.style.borderColor = "var(--danger)";
            warningDiv.style.background = "rgba(255, 23, 68, 0.05)";
            warningDiv.style.color = "var(--danger)";
            warningDiv.style.marginTop = "1rem";
            warningDiv.innerHTML = `
                <strong>Cảnh báo lệch khóa!</strong><br>
                Khóa trên trình duyệt không khớp với khóa của dữ liệu cũ trên Cloud Server. 
                Vui lòng bấm nút <strong>RESET DATABASE</strong> trong phần Cơ sở dữ liệu đám mây để đồng bộ nhóm toán học.
            `;
            this.keyInfoContainer.parentNode.insertBefore(warningDiv, this.keyInfoContainer.nextSibling);
        }
    },
    
    hideKeyMismatchWarning() {
        const warningDiv = document.getElementById("key-mismatch-warning");
        if (warningDiv) {
            warningDiv.remove();
        }
    },
    
    // Render Products Table
    renderProductTable() {
        const thPlaintext = document.getElementById("th-plaintext");
        const thCiphertext = document.getElementById("th-ciphertext");
        
        if (this.state.isTableDecrypted) {
            if (thPlaintext) thPlaintext.style.display = "";
            if (thCiphertext) thCiphertext.style.width = "40%";
        } else {
            if (thPlaintext) thPlaintext.style.display = "none";
            if (thCiphertext) thCiphertext.style.width = "60%";
        }

        if (this.state.products.length === 0) {
            this.productTableBody.innerHTML = `
                <tr>
                    <td colspan="${this.state.isTableDecrypted ? 4 : 3}" class="text-center text-muted py-4">
                        Chưa có sản phẩm nào được tải lên Cloud.
                    </td>
                </tr>
            `;
            if (this.visProductSelect) {
                this.visProductSelect.innerHTML = `<option value="">-- Chưa có sản phẩm --</option>`;
            }
            return;
        }
        
        let html = "";
        let visualizerSelectHtml = `<option value="">-- Chọn sản phẩm --</option>`;
        
        this.state.products.forEach(p => {
            let decryptedPriceTd = "";
            if (this.state.isTableDecrypted) {
                let decryptedPrice = "N/A";
                const cachedDecrypted = this.state.decryptedPrices[p.name];
                if (cachedDecrypted !== undefined) {
                    decryptedPrice = parseInt(cachedDecrypted).toLocaleString();
                } else if (this.state.privateKey) {
                    decryptedPrice = "Đang giải mã...";
                }
                decryptedPriceTd = `<td class="plaintext-cell mono">${decryptedPrice}</td>`;
            }

            html += `
                <tr>
                    <td class="mono">${p.id}</td>
                    <td><strong>${this.escapeHTML(p.name)}</strong></td>
                    <td class="ciphertext-cell mono" onclick="navigator.clipboard.writeText('${p.encrypted_price}'); App.showToast('Đã copy ciphertext sản phẩm ${p.id}!', 'success');" title="Click để copy toàn bộ ciphertext">
                        ${p.encrypted_price}
                    </td>
                    ${decryptedPriceTd}
                </tr>
            `;
            
            // Only add to mathematical visualizer if we have the localVisStore encrypted data for it
            const inLocalStore = this.state.localVisStore[p.name] !== undefined;
            const labelSuffix = inLocalStore ? " (Đầy đủ bước tính)" : " (Ciphertext duy nhất)";
            visualizerSelectHtml += `<option value="${p.name}">${p.id}. ${this.escapeHTML(p.name)}${labelSuffix}</option>`;
        });
        
        this.productTableBody.innerHTML = html;
        if (this.visProductSelect) {
            this.visProductSelect.innerHTML = visualizerSelectHtml;
        }
    },
    
    // Update dashboard metrics
    updateStats() {
        const count = this.state.products.length;
        this.productCount.innerText = count;
        this.statProductsCount.innerText = count;
        
        this.enableSecureInputs(this.state.publicKey !== null);
    },
    
    // Add single product locally and upload encrypted value
    async addSingleProduct() {
        if (!this.state.publicKey) return;
        
        const name = this.prodName.value.trim();
        const priceVal = parseInt(this.prodPrice.value);
        
        if (!name || isNaN(priceVal) || priceVal < 0) {
            this.showToast("Tên và giá sản phẩm không hợp lệ!", "warning");
            return;
        }
        
        this.btnAddProduct.disabled = true;
        this.btnAddProduct.innerText = "Đang mã hóa & Upload...";
        
        try {
            // 1. Client-Side Paillier Encryption (Zero Knowledge!)
            const encryptionResult = await callWorker('encrypt_single', { price: priceVal, pubKeyN: this.state.publicKey.n });
            
            // Store the plaintext price in the decryption cache since client already knows it!
            this.state.decryptedPrices[name] = priceVal.toString();
            
            // Save the exact parameters locally for the step-by-step visualizer
            this.state.localVisStore[name] = encryptionResult.visData;
            
            // 2. Upload ciphertext to untrusted server
            const payload = {
                public_key_n: this.state.publicKey.n,
                products: [
                    {
                        name: name,
                        encrypted_price: encryptionResult.ciphertext
                    }
                ]
            };
            
            const res = await fetch("/api/upload", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.message || "Tải lên thất bại");
            }
            
            // Clear inputs and reload table
            this.prodName.value = "";
            this.prodPrice.value = "";
            await this.fetchProducts();
            
            // Auto-select the newly added product in visualizer
            if (this.visProductSelect) {
                this.visProductSelect.value = name;
                this.updateStepVisualizer(name);
            }
            
            this.showToast(`Sản phẩm '${name}' đã được mã hóa thành công!`, "success");
        } catch (e) {
            console.error("Product upload error", e);
            this.showToast(`Lỗi: ${e.message}`, "danger");
        } finally {
            this.btnAddProduct.disabled = false;
            this.btnAddProduct.innerText = "Mã hóa & Tải lên Cloud";
        }
    },
    
    // Parse CSV and batch encrypt + upload
    async handleCsvFile(file) {
        if (!file) return;
        if (!this.state.publicKey) {
            this.showToast("Vui lòng tạo khóa trước khi upload CSV!", "warning");
            return;
        }
        
        const reader = new FileReader();
        reader.onload = async (e) => {
            const text = e.target.result;
            const lines = text.split(/\r?\n/);
            const parsedProducts = [];
            
            // Parse CSV lines
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;
                
                const parts = line.split(',');
                if (parts.length >= 2) {
                    const name = parts[0].trim();
                    const price = parseInt(parts[1].trim());
                    if (name && !isNaN(price) && price >= 0) {
                        parsedProducts.push({ name, price });
                    }
                }
            }
            
            if (parsedProducts.length === 0) {
                this.showToast("Không tìm thấy sản phẩm hợp lệ nào trong file CSV. Định dạng yêu cầu: tên,giá", "warning");
                return;
            }
            
            // Batch encrypting and uploading
            this.csvProgressContainer.style.display = "block";
            this.csvProgressPercent.innerText = "0%";
            this.csvProgressBar.value = 0;
            this.csvProgressText.innerText = `Đang mã hóa 0/${parsedProducts.length} sản phẩm...`;
            
            try {
                // Offload batch encryption to Web Worker
                const result = await callWorker(
                    'encrypt_batch',
                    { products: parsedProducts, pubKeyN: this.state.publicKey.n },
                    ({ percent, current, total }) => {
                        this.csvProgressPercent.innerText = `${percent}%`;
                        this.csvProgressBar.value = percent / 100;
                        this.csvProgressText.innerText = `Mã hóa và chuẩn bị: ${current}/${total} sản phẩm...`;
                    }
                );
                
                const { products, localVisStore } = result;
                
                // Add the plaintext prices to our decryptedPrices cache immediately!
                parsedProducts.forEach(p => {
                    this.state.decryptedPrices[p.name] = p.price.toString();
                });
                
                // Upload to server
                this.csvProgressText.innerText = `Đang đồng bộ hóa dữ liệu lên Cloud Database...`;
                const payload = {
                    public_key_n: this.state.publicKey.n,
                    products
                };
                
                const res = await fetch("/api/upload", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                
                if (!res.ok) {
                    const errData = await res.json();
                    throw new Error(errData.message || "Tải lên CSV thất bại");
                }
                
                // Merge temporary session visualizers
                Object.assign(this.state.localVisStore, localVisStore);
                
                await this.fetchProducts();
                this.showToast(`Đã mã hóa thành công ${parsedProducts.length} sản phẩm từ file CSV!`, "success");
            } catch (err) {
                console.error(err);
                this.showToast(`Lỗi upload CSV: ${err.message}`, "danger");
            } finally {
                this.csvProgressContainer.style.display = "none";
                this.csvFileInput.value = "";
            }
        };
        reader.readAsText(file);
    },
    
    // Clear and reset SQLite DB
    async resetDatabase() {
        if (!confirm("CẢNH BÁO: Hành động này sẽ xóa toàn bộ dữ liệu trên Cloud Database và cấu hình khóa hiện tại. Bạn có chắc chắn muốn tiếp tục?")) return;
        
        try {
            const res = await fetch("/api/reset", { method: "POST" });
            if (!res.ok) throw new Error("Reset failed");
            
            this.state.products = [];
            this.state.encryptedSum = null;
            this.state.decryptedSum = null;
            this.state.isTableDecrypted = false;
            this.state.localSum = null;
            this.state.localVisStore = {};
            this.state.decryptedPrices = {};
            
            const gaugeFill = document.getElementById("local-sum-gauge-fill");
            if (gaugeFill) {
                gaugeFill.style.strokeDashoffset = "251.2";
                gaugeFill.style.stroke = "var(--accent-coral)";
            }
            
            this.renderProductTable();
            this.updateStats();
            
            if (this.sumResultsArea) this.sumResultsArea.style.display = "none";
            if (this.decryptedResultBox) this.decryptedResultBox.style.display = "none";
            if (this.localSumResultsArea) this.localSumResultsArea.style.display = "none";
            if (this.btnDecryptAllTable) {
                this.btnDecryptAllTable.innerText = "Giải mã";
                this.btnDecryptAllTable.className = "btn btn-secondary btn-xs";
            }
            
            // Optionally clear client localStorage keys as well
            localStorage.removeItem("shadowdb_keys");
            this.state.publicKey = null;
            this.state.privateKey = null;
            this.pubKeyN.innerText = "N/A";
            this.privKeyLambda.innerText = "N/A";
            this.privKeyMu.innerText = "N/A";
            this.keyInfoContainer.style.display = "none";
            this.noKeysAlert.style.display = "block";
            this.statKeyStatus.innerText = "Chưa có";
            this.statKeyStatus.style.color = "var(--text-muted)";
            
            // Clear manual inputs & results
            const manualM = document.getElementById("manual-m");
            const manualPubN = document.getElementById("manual-pub-n");
            const manualCResultBox = document.getElementById("manual-c-result-box");
            const manualCResult = document.getElementById("manual-c-result");
            
            const manualC = document.getElementById("manual-c");
            const manualPrivLambda = document.getElementById("manual-priv-lambda");
            const manualPrivMu = document.getElementById("manual-priv-mu");
            const manualPrivN = document.getElementById("manual-priv-n");
            const manualMResultBox = document.getElementById("manual-m-result-box");
            const manualMResult = document.getElementById("manual-m-result");
            
            if (manualM) manualM.value = "";
            if (manualPubN) manualPubN.value = "";
            if (manualCResultBox) manualCResultBox.style.display = "none";
            if (manualCResult) manualCResult.innerText = "";
            
            if (manualC) manualC.value = "";
            if (manualPrivLambda) manualPrivLambda.value = "";
            if (manualPrivMu) manualPrivMu.value = "";
            if (manualPrivN) manualPrivN.value = "";
            if (manualMResultBox) manualMResultBox.style.display = "none";
            if (manualMResult) manualMResult.innerText = "";
            
            this.showToast("Đã reset sạch database trên Cloud và khóa local!", "success");
        } catch (e) {
            console.error("Database reset error", e);
            this.showToast("Reset database thất bại.", "danger");
        }
    },
    
    // Call server homomorphic sum API
    async calculateHomomorphicSum() {
        if (this.state.products.length === 0) return;
        
        this.btnCalculateSum.disabled = true;
        this.btnCalculateSum.innerText = "SERVER ĐANG NHÂN CIPHERTEXTS...";
        
        try {
            const startTime = performance.now();
            const res = await fetch("/api/homomorphic-sum", { method: "POST" });
            
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.message || "Tích hợp phép tính lỗi");
            }
            
            const duration = (performance.now() - startTime).toFixed(1);
            const data = await responseLogJSON(res);
            console.log(`Server homomorphic sum calculated in ${duration}ms.`);
            
            this.state.encryptedSum = data.encrypted_sum;
            this.resultEncryptedSum.innerText = data.encrypted_sum;
            
            this.sumResultsArea.style.display = "flex";
            this.decryptedResultBox.style.display = "none";
            
            // Scroll to results
            this.sumResultsArea.scrollIntoView({ behavior: 'smooth' });
            
            // Update visualizer calculations
            this.updateHomoSumVisualizer();
        } catch (e) {
            console.error("Homomorphic sum failed", e);
            this.showToast(`Lỗi: ${e.message}`, "danger");
        } finally {
            this.btnCalculateSum.disabled = false;
            this.btnCalculateSum.innerText = "TÌNH TỔNG ĐỒNG CẤU TRÊN CLOUD";
        }
    },
    
    // Decrypt the homomorphic summation in browser
    async decryptHomomorphicSum() {
        if (!this.state.privateKey || !this.state.encryptedSum) return;
        
        this.btnDecryptSum.disabled = true;
        this.btnDecryptSum.innerText = "ĐANG GIẢI MÃ (LOCAL)...";
        
        try {
            const startTime = performance.now();
            const decryptedVal = await callWorker('decrypt_single', { ciphertext: this.state.encryptedSum, privateKey: this.state.privateKey });
            const duration = (performance.now() - startTime).toFixed(2);
            console.log(`Decrypted sum in ${duration}ms client-side.`);
            
            this.state.decryptedSum = decryptedVal;
            this.decryptedSumVal.innerText = parseInt(decryptedVal).toLocaleString();
            
            this.decryptedResultBox.style.display = "flex";
            
            // Verify correctness compared to visual plaintext sum of local elements if we have all in session
            let plainSum = 0n;
            let fullyMatchedLocal = true;
            
            this.state.products.forEach(p => {
                const name = p.name;
                if (this.state.localVisStore[name]) {
                    plainSum += BigInt(this.state.localVisStore[name].m);
                } else {
                    fullyMatchedLocal = false; // missing local plaintext price (created in a different session)
                }
            });
            
            const gaugeFill = document.getElementById("local-sum-gauge-fill");
            if (fullyMatchedLocal) {
                if (BigInt(decryptedVal) === plainSum) {
                    this.verificationStatus.className = "verification-badge-pill";
                    this.verificationStatus.innerText = `KHỚP HOÀN TOÀN (TỔNG: ${plainSum.toLocaleString()})`;
                    if (gaugeFill) {
                        gaugeFill.style.stroke = "var(--accent-green)";
                    }
                } else {
                    this.verificationStatus.className = "verification-badge-pill";
                    this.verificationStatus.style.background = "var(--accent-coral)";
                    this.verificationStatus.innerText = `KHÔNG KHỚP`;
                    if (gaugeFill) {
                        gaugeFill.style.stroke = "var(--accent-coral)";
                    }
                }
            } else {
                this.verificationStatus.className = "verification-badge-pill";
                this.verificationStatus.innerText = `XÁC THỰC THÀNH CÔNG`;
                if (gaugeFill) {
                    gaugeFill.style.stroke = "var(--accent-green)";
                }
            }
        } catch (e) {
            console.error("Decryption failed", e);
            this.showToast(`Lỗi giải mã: ${e.message}`, "danger");
        } finally {
            this.btnDecryptSum.disabled = false;
            this.btnDecryptSum.innerText = "GIẢI MÃ TỔNG ĐỒNG CẤU TẠI CLIENT";
        }
    },
    
    // Update individual mathematical visualization step-by-step
    updateStepVisualizer(prodName) {
        if (!this.visProductSelect || !this.visDetailsArea || !this.visNoData) return;
        if (!prodName) {
            this.visDetailsArea.style.display = "none";
            this.visNoData.style.display = "block";
            return;
        }
        
        const data = this.state.localVisStore[prodName];
        if (!data) {
            // Find in products
            const prod = this.state.products.find(p => p.name === prodName);
            if (prod) {
                this.visM.innerText = "Ẩn (Không có trong session hiện tại)";
                this.visR.innerText = "Ẩn (Không có trong session hiện tại)";
                this.visC.innerText = prod.encrypted_price;
                this.visDetailsArea.style.display = "block";
                this.visNoData.style.display = "none";
            }
            return;
        }
        
        this.visM.innerText = data.m;
        this.visR.innerText = data.r;
        this.visC.innerText = data.c;
        
        this.visDetailsArea.style.display = "block";
        this.visNoData.style.display = "none";
    },
    
    // Update homomorphic multiplication summation equation
    updateHomoSumVisualizer() {
        if (!this.visHomoCalcArea || !this.visHomoCalcExpression) return;
        if (!this.state.encryptedSum || this.state.products.length === 0) return;
        
        let expression = "";
        const limit = 4;
        const productsToUse = this.state.products.slice(0, limit);
        
        const ciphers = productsToUse.map(p => {
            const shortStr = p.encrypted_price.substring(0, 10) + "...";
            return `[C_${p.id}: ${shortStr}]`;
        });
        
        expression = ciphers.join(" × ");
        if (this.state.products.length > limit) {
            expression += ` × ... (${this.state.products.length - limit} ciphertexts khác)`;
        }
        
        expression += ` mod n²\n\n= ${this.state.encryptedSum.substring(0, 30)}... (Tổng số có độ dài ${this.state.encryptedSum.length} kí tự)`;
        
        this.visHomoCalcExpression.innerText = expression;
        this.visHomoCalcArea.style.display = "block";
    },

    // --- Theme Engine ---
    initTheme() {
        document.documentElement.setAttribute("data-theme", "light");
    },
    
    toggleTheme() {
        // Theme toggling disabled by default
    },
    
    updateThemeToggleUI(theme) {
        // Theme toggling disabled by default
    },
    
    // --- Table Decryption Toggle ---
    async toggleTableDecryption() {
        if (!this.state.privateKey) return;
        
        if (!this.state.isTableDecrypted) {
            // Turning it ON: decrypt any missing prices first
            const productsToDecrypt = this.state.products.filter(p => this.state.decryptedPrices[p.name] === undefined);
            if (productsToDecrypt.length > 0) {
                this.btnDecryptAllTable.disabled = true;
                this.btnDecryptAllTable.innerText = "Đang giải mã...";
                try {
                    const ciphertexts = productsToDecrypt.map(p => p.encrypted_price);
                    const results = await callWorker('decrypt_batch', { ciphertexts, privateKey: this.state.privateKey });
                    productsToDecrypt.forEach((p, idx) => {
                        this.state.decryptedPrices[p.name] = results[idx];
                    });
                } catch (e) {
                    console.error("Batch decryption failed", e);
                    this.showToast("Lỗi giải mã bảng: " + e.message, "danger");
                    this.btnDecryptAllTable.disabled = false;
                    this.btnDecryptAllTable.innerText = "Giải mã";
                    return;
                } finally {
                    this.btnDecryptAllTable.disabled = false;
                }
            }
            this.state.isTableDecrypted = true;
        } else {
            // Turning it OFF
            this.state.isTableDecrypted = false;
        }
        
        if (this.btnDecryptAllTable) {
            this.btnDecryptAllTable.innerText = this.state.isTableDecrypted ? "Ẩn" : "Giải mã";
            this.btnDecryptAllTable.className = this.state.isTableDecrypted ? "btn btn-secondary btn-xs active" : "btn btn-secondary btn-xs";
        }
        
        this.renderProductTable();
        this.showToast(this.state.isTableDecrypted ? "Đã giải mã toàn bộ dữ liệu bảng tại Client!" : "Đã ẩn dữ liệu bản rõ giải mã!", "success");
    },
    
    // --- Local Plaintext Summation ---
    async calculateLocalSum() {
        if (!this.state.privateKey || this.state.products.length === 0) return;
        
        this.btnCalculateLocalSum.disabled = true;
        this.btnCalculateLocalSum.innerText = "Đang giải mã...";
        
        try {
            const startTime = performance.now();
            const ciphertexts = this.state.products.map(p => p.encrypted_price);
            const decryptedValues = await callWorker('decrypt_batch', { ciphertexts, privateKey: this.state.privateKey });
            
            let sum = 0n;
            decryptedValues.forEach(decVal => {
                sum += BigInt(decVal);
            });
            const duration = (performance.now() - startTime).toFixed(2);
            console.log(`Decrypted ${ciphertexts.length} local items in ${duration}ms via Web Worker.`);
            
            this.state.localSum = sum.toString();
            if (this.localSumVal) {
                this.localSumVal.innerText = parseInt(this.state.localSum).toLocaleString();
            }
            const gaugeFill = document.getElementById("local-sum-gauge-fill");
            if (gaugeFill) {
                gaugeFill.style.strokeDashoffset = "0";
            }
            if (this.localSumResultsArea) {
                this.localSumResultsArea.style.display = "block";
            }
            this.showToast("Đã tính tổng trên local thành công!", "success");
        } catch (e) {
            console.error("Local sum calculation failed", e);
            this.showToast("Lỗi tính tổng cục bộ: " + e.message, "danger");
        } finally {
            this.btnCalculateLocalSum.disabled = false;
            this.btnCalculateLocalSum.innerText = "Tính tổng trên Local";
        }
    },
    
    // HTML Escaper utility
    escapeHTML(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    // Toast Notification System
    showToast(message, type = "info") {
        const container = document.getElementById("toast-container");
        if (!container) return;
        
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerText = message;
        
        container.appendChild(toast);
        
        // Remove toast after animation finishes (3 seconds)
        setTimeout(() => {
            toast.remove();
        }, 3000);
    },

    bindManualCalculator() {
        const btnManualEncrypt = document.getElementById("btn-manual-encrypt");
        const btnManualDecrypt = document.getElementById("btn-manual-decrypt");
        
        const manualCResult = document.getElementById("manual-c-result");
        const manualMResult = document.getElementById("manual-m-result");
        
        if (btnManualEncrypt) {
            btnManualEncrypt.addEventListener("click", async () => {
                const mInput = document.getElementById("manual-m").value.trim();
                const nInput = document.getElementById("manual-pub-n").value.trim();
                const resultBox = document.getElementById("manual-c-result-box");
                
                if (!mInput || !nInput) {
                    this.showToast("Vui lòng điền đủ Bản rõ m và Khóa công khai n!", "warning");
                    return;
                }
                
                try {
                    const mBI = BigInt(mInput);
                    const nBI = BigInt(nInput);
                    
                    if (mBI < 0n) {
                        this.showToast("Bản rõ m không được phép là số âm!", "danger");
                        return;
                    }
                    if (mBI >= nBI) {
                        this.showToast("Lỗi toán học: Bản rõ m phải nhỏ hơn khóa công khai n!", "danger");
                        return;
                    }
                    
                    btnManualEncrypt.disabled = true;
                    btnManualEncrypt.innerText = "Đang mã hóa...";
                    
                    const result = await callWorker('encrypt_single', { price: mBI.toString(), pubKeyN: nBI.toString() });
                    if (manualCResult) {
                        manualCResult.innerText = result.ciphertext;
                    }
                    if (resultBox) {
                        resultBox.style.display = "block";
                    }
                    this.showToast("Mã hóa thủ công thành công!", "success");
                } catch (e) {
                    console.error("Manual encryption error", e);
                    this.showToast("Lỗi mã hóa: " + e.message, "danger");
                } finally {
                    btnManualEncrypt.disabled = false;
                    btnManualEncrypt.innerText = "Mã hóa";
                }
            });
        }
        
        if (btnManualDecrypt) {
            btnManualDecrypt.addEventListener("click", async () => {
                const cInput = document.getElementById("manual-c").value.trim();
                const lambdaInput = document.getElementById("manual-priv-lambda").value.trim();
                const muInput = document.getElementById("manual-priv-mu").value.trim();
                const nInput = document.getElementById("manual-priv-n").value.trim();
                const resultBox = document.getElementById("manual-m-result-box");
                
                if (!cInput || !lambdaInput || !muInput || !nInput) {
                    this.showToast("Vui lòng điền đầy đủ Ciphertext c và các Khóa riêng tư!", "warning");
                    return;
                }
                
                try {
                    const cBI = BigInt(cInput);
                    const lambdaBI = BigInt(lambdaInput);
                    const muBI = BigInt(muInput);
                    const nBI = BigInt(nInput);
                    const nSq = nBI * nBI;
                    
                    if (cBI <= 0n || cBI >= nSq) {
                        this.showToast("Lỗi toán học: Ciphertext c phải thỏa mãn 0 < c < n^2!", "danger");
                        return;
                    }
                    
                    const privKey = {
                        lambda: lambdaBI.toString(),
                        mu: muBI.toString(),
                        n: nBI.toString()
                    };
                    
                    btnManualDecrypt.disabled = true;
                    btnManualDecrypt.innerText = "Đang giải mã...";
                    
                    const result = await callWorker('decrypt_single', { ciphertext: cBI.toString(), privateKey: privKey });
                    if (manualMResult) {
                        manualMResult.innerText = result;
                    }
                    if (resultBox) {
                        resultBox.style.display = "block";
                    }
                    this.showToast("Giải mã thủ công thành công!", "success");
                } catch (e) {
                    console.error("Manual decryption error", e);
                    this.showToast("Lỗi giải mã: " + e.message, "danger");
                } finally {
                    btnManualDecrypt.disabled = false;
                    btnManualDecrypt.innerText = "Giải mã";
                }
            });
        }
        
        // Add copy-on-click for results
        if (manualCResult) {
            manualCResult.addEventListener("click", () => {
                const text = manualCResult.innerText;
                if (text) {
                    this.copyToClipboard(text, "Ciphertext c");
                }
            });
        }
        
        if (manualMResult) {
            manualMResult.addEventListener("click", () => {
                const text = manualMResult.innerText;
                if (text) {
                    this.copyToClipboard(text, "Bản rõ m");
                }
            });
        }
    }
};

// Helper for parsing json body safely
async function responseLogJSON(response) {
    const text = await response.text();
    try {
        return JSON.parse(text);
    } catch (e) {
        throw new Error(`Invalid JSON output: ${text.substring(0, 100)}`);
    }
}

// Start app on DOM Loaded
document.addEventListener("DOMContentLoaded", () => App.init());
