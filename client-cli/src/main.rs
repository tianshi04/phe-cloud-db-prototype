use num_bigint::BigUint;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::time::Instant;

const CSV_PATH: &str = "data/product_prices.csv";
const SERVER_URL: &str = "http://127.0.0.1:8000/api";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ProductRecord {
    name: String,
    price: u32,
}

#[derive(Serialize)]
struct UploadRequest {
    public_key_n: String,
    products: Vec<EncryptedProductInput>,
}

#[derive(Serialize)]
struct EncryptedProductInput {
    name: String,
    encrypted_price: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct GenericResponse {
    status: String,
    #[serde(default)]
    message: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct SumResponse {
    status: String,
    #[serde(default)]
    encrypted_sum: String,
    #[serde(default)]
    message: String,
}

struct BenchmarkResult {
    key_size: usize,
    key_gen_ms: f64,
    encryption_ms: f64,
    plaintext_sum_ms: f64,
    homomorphic_sum_ms: f64,
    verification: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================================");
    println!("     PARTIALLY HOMOMORPHIC ENCRYPTION CLIENT BENCHMARK   ");
    println!("=========================================================");

    // 1. Generate/Check synthetic dataset
    generate_synthetic_data(1000)?;

    // 2. Setup reqwest client
    let http_client = reqwest::Client::new();

    // Check server status
    if let Err(e) = http_client
        .post(format!("{}/reset", SERVER_URL))
        .send()
        .await
    {
        eprintln!("Error: Cannot connect to Axum Server at {}.", SERVER_URL);
        eprintln!("Please ensure the cloud-server is running by running `cargo run --release -p cloud-server` first.");
        eprintln!("Technical details: {}", e);
        std::process::exit(1);
    }

    let key_sizes = vec![128, 256, 512, 1024];
    let mut results = Vec::new();

    for &size in &key_sizes {
        println!("\n>>> Running Benchmark for Key Size: {} bits", size);

        // A. Key Generation
        print!("  [1/6] Generating Keypair... ");
        std::io::stdout().flush()?;
        let start = Instant::now();
        let (pk, sk) = paillier_crypto::generate_keys(size);
        let key_gen_duration = start.elapsed().as_secs_f64() * 1000.0;
        println!("Done! ({:.2} ms)", key_gen_duration);

        // B. Read Product Data
        let products = read_synthetic_data()?;
        let count = products.len();

        // C. Local Encryption
        print!("  [2/6] Encrypting {} prices locally... ", count);
        std::io::stdout().flush()?;
        let start = Instant::now();
        let mut encrypted_inputs = Vec::with_capacity(count);
        for p in &products {
            let m = BigUint::from(p.price);
            let c = pk.encrypt(&m);
            encrypted_inputs.push(EncryptedProductInput {
                name: p.name.clone(),
                encrypted_price: c.to_string(),
            });
        }
        let encryption_duration = start.elapsed().as_secs_f64() * 1000.0;
        println!("Done! ({:.2} ms)", encryption_duration);

        // D. Upload to Server
        print!("  [3/6] Uploading encrypted data to cloud server... ");
        std::io::stdout().flush()?;
        // First reset server
        let _ = http_client
            .post(format!("{}/reset", SERVER_URL))
            .send()
            .await?;

        let upload_req = UploadRequest {
            public_key_n: pk.n.to_string(),
            products: encrypted_inputs,
        };

        let upload_res = http_client
            .post(format!("{}/upload", SERVER_URL))
            .json(&upload_req)
            .send()
            .await?;

        if !upload_res.status().is_success() {
            let err_body: GenericResponse = upload_res.json().await?;
            eprintln!("Upload failed: {}", err_body.message);
            continue;
        }
        println!("Done! (Stored securely in SQLite)");

        // E. Plaintext SUM Baseline
        print!("  [4/6] Computing local Plaintext SUM (Baseline)... ");
        std::io::stdout().flush()?;
        let start = Instant::now();
        let mut plaintext_sum = 0u64;
        for p in &products {
            plaintext_sum += p.price as u64;
        }
        let plaintext_sum_duration = start.elapsed().as_secs_f64() * 1000.0;
        println!(
            "Done! SUM = {} ({:.4} ms)",
            plaintext_sum, plaintext_sum_duration
        );

        // F. Call Cloud Server for Homomorphic SUM
        print!("  [5/6] Requesting Zero-Knowledge SUM from server... ");
        std::io::stdout().flush()?;
        let start = Instant::now();
        let sum_res = http_client
            .post(format!("{}/homomorphic-sum", SERVER_URL))
            .send()
            .await?;

        let sum_duration = start.elapsed().as_secs_f64() * 1000.0;

        if !sum_res.status().is_success() {
            let err_body: GenericResponse = sum_res.json().await?;
            eprintln!("Server SUM calculation failed: {}", err_body.message);
            continue;
        }

        let sum_data: SumResponse = sum_res.json().await?;
        let encrypted_sum = BigUint::from_str(&sum_data.encrypted_sum)?;
        println!(
            "Done! (Calculated by server mod n^2 in {:.2} ms)",
            sum_duration
        );

        // G. Decrypt and Verify
        print!("  [6/6] Decrypting and verifying cloud result... ");
        std::io::stdout().flush()?;
        let decrypted_sum = sk.decrypt(&encrypted_sum, &pk);
        let expected_sum = BigUint::from(plaintext_sum);

        let verification_status = if decrypted_sum == expected_sum {
            println!("MATCHED! Correctness verified.");
            "PASSED"
        } else {
            println!(
                "MISMATCH! Decrypted: {}, Plaintext Sum: {}",
                decrypted_sum, expected_sum
            );
            "FAILED"
        };

        results.push(BenchmarkResult {
            key_size: size,
            key_gen_ms: key_gen_duration,
            encryption_ms: encryption_duration,
            plaintext_sum_ms: plaintext_sum_duration,
            homomorphic_sum_ms: sum_duration,
            verification: verification_status,
        });
    }

    // 3. Print beautiful benchmark report
    println!("\n================================================================================================");
    println!("                                     FINAL BENCHMARK REPORT                                     ");
    println!("================================================================================================");
    println!("| Key Size (bits) | Keygen (ms) | Encrypt 1000 (ms) | Plaintext Sum (ms) | Homomorphic Sum (ms) | Verification |");
    println!("|-----------------|-------------|-------------------|--------------------|----------------------|--------------|");
    for r in results {
        println!(
            "| {:<15} | {:<11.2} | {:<17.2} | {:<18.4} | {:<20.2} | {:<12} |",
            r.key_size,
            r.key_gen_ms,
            r.encryption_ms,
            r.plaintext_sum_ms,
            r.homomorphic_sum_ms,
            r.verification
        );
    }
    println!("================================================================================================");
    println!("Notice: In Paillier cryptography, real prices are scaled to integers (e.g. cents).");
    println!("The server calculates the encrypted SUM securely using ciphertext multiplication modulo n^2.");
    println!("Zero knowledge is maintained: The server never knows individual prices or the final sum value.");
    println!("================================================================================================");

    Ok(())
}

/// Generates 1,000 synthetic products with random prices into a CSV file if not already present.
fn generate_synthetic_data(num_records: usize) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(CSV_PATH).exists() {
        println!(
            "Synthetic dataset already exists at '{}'. Skipping generation.",
            CSV_PATH
        );
        return Ok(());
    }

    println!("Generating {} synthetic product records...", num_records);
    if let Some(parent) = Path::new(CSV_PATH).parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(CSV_PATH)?;
    writeln!(file, "name,price")?;

    let mut rng = rand::thread_rng();
    for i in 1..=num_records {
        // Generate random price between 10 and 1000
        let price = rng.gen_range(10..1000);
        writeln!(file, "Product #{:04},{}", i, price)?;
    }

    println!("Dataset generated successfully at '{}'.", CSV_PATH);
    Ok(())
}

/// Reads synthetic dataset from CSV.
fn read_synthetic_data() -> Result<Vec<ProductRecord>, Box<dyn std::error::Error>> {
    let file = File::open(CSV_PATH)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(file);
    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: ProductRecord = result?;
        records.push(record);
    }

    Ok(records)
}
