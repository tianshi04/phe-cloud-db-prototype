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
    #[serde(default)]
    calculation_time_ms: f64,
}

struct BenchmarkResult {
    key_size: usize,
    key_gen_ms: f64,
    encryption_ms: f64,
    homomorphic_sum_ms: f64,
    verification: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================================");
    println!("     PARTIALLY HOMOMORPHIC ENCRYPTION CLIENT BENCHMARK   ");
    println!("=========================================================");

    // 1. Generate/Check synthetic dataset
    generate_synthetic_data(CSV_PATH, 1000)?;

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

    // Measure Plaintext SUM Baseline once (constant for dataset)
    let products = read_synthetic_data(CSV_PATH)?;
    let count = products.len();

    println!("\n=== BASELINE MEASUREMENT ===");
    print!("Computing local Plaintext SUM (Constant Baseline)... ");
    std::io::stdout().flush()?;
    let start_plaintext = Instant::now();
    let mut plaintext_sum = 0u64;
    for p in &products {
        plaintext_sum += p.price as u64;
    }
    let plaintext_sum_duration = start_plaintext.elapsed().as_secs_f64() * 1000.0;
    println!(
        "Done! SUM = {} ({:.4} ms)",
        plaintext_sum, plaintext_sum_duration
    );
    println!("============================\n");

    let key_sizes = vec![256, 512, 1024, 2048];
    let mut results = Vec::new();

    for &size in &key_sizes {
        println!("\n>>> Running Benchmark for Key Size: {} bits", size);

        // A. Key Generation
        print!("  [1/5] Generating Keypair... ");
        std::io::stdout().flush()?;
        let start = Instant::now();
        let (pk, sk) = paillier_crypto::generate_keys(size);
        let key_gen_duration = start.elapsed().as_secs_f64() * 1000.0;
        println!("Done! ({:.2} ms)", key_gen_duration);

        // B. Local Encryption
        print!("  [2/5] Encrypting {} prices locally... ", count);
        std::io::stdout().flush()?;
        let start = Instant::now();
        let mut encrypted_inputs = Vec::with_capacity(count);
        for p in &products {
            let m = BigUint::from(p.price);
            let c = pk.encrypt(&m).expect("encryption failed");
            encrypted_inputs.push(EncryptedProductInput {
                name: p.name.clone(),
                encrypted_price: c.to_string(),
            });
        }
        let encryption_duration = start.elapsed().as_secs_f64() * 1000.0;
        println!("Done! ({:.2} ms)", encryption_duration);

        // C. Upload to Server
        print!("  [3/5] Uploading encrypted data to cloud server... ");
        std::io::stdout().flush()?;
        // First reset server
        let _ = http_client
            .post(format!("{}/reset", SERVER_URL))
            .send()
            .await?;

        let upload_req = UploadRequest {
            public_key_n: pk.n().to_string(),
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

        // D. Call Cloud Server for Homomorphic SUM
        print!("  [4/5] Requesting Zero-Knowledge SUM from server... ");
        std::io::stdout().flush()?;
        let start = Instant::now();
        let sum_res = http_client
            .post(format!("{}/homomorphic-sum", SERVER_URL))
            .send()
            .await?;

        let rtt_duration = start.elapsed().as_secs_f64() * 1000.0;

        if !sum_res.status().is_success() {
            let err_body: GenericResponse = sum_res.json().await?;
            eprintln!("Server SUM calculation failed: {}", err_body.message);
            continue;
        }

        let sum_data: SumResponse = sum_res.json().await?;
        let encrypted_sum = BigUint::from_str(&sum_data.encrypted_sum)?;
        let sum_duration = sum_data.calculation_time_ms;
        println!(
            "Done! (Server computation: {:.4} ms | Network RTT: {:.2} ms)",
            sum_duration, rtt_duration
        );

        // E. Decrypt and Verify
        print!("  [5/5] Decrypting and verifying cloud result... ");
        std::io::stdout().flush()?;
        let decrypted_sum = sk.decrypt(&encrypted_sum).expect("decryption failed");
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
            homomorphic_sum_ms: sum_duration,
            verification: verification_status,
        });
    }

    // 3. Print beautiful benchmark report
    println!("\n========================================================================================");
    println!("                                 FINAL BENCHMARK REPORT                                 ");
    println!("========================================================================================");
    println!("| Key Size (bits) | Keygen (ms) | Encrypt 1000 (ms) | Server Sum (ms)  | Verification |");
    println!("|-----------------|-------------|-------------------|------------------|--------------|");
    for r in results {
        println!(
            "| {:<15} | {:<11.2} | {:<17.2} | {:<16.4} | {:<12} |",
            r.key_size,
            r.key_gen_ms,
            r.encryption_ms,
            r.homomorphic_sum_ms,
            r.verification
        );
    }
    println!("========================================================================================");
    println!("Baseline Plaintext SUM (Constant): {} ({:.4} ms)", plaintext_sum, plaintext_sum_duration);
    println!("================================================================================================");
    println!("Notice: In Paillier cryptography, real prices are scaled to integers (e.g. cents).");
    println!("The server calculates the encrypted SUM securely using ciphertext multiplication modulo n^2.");
    println!("Zero knowledge is maintained: The server never knows individual prices or the final sum value.");
    println!("================================================================================================");

    Ok(())
}

/// Generates 1,000 synthetic products with random prices into a CSV file if not already present.
fn generate_synthetic_data(path: &str, num_records: usize) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        println!(
            "Synthetic dataset already exists at '{}'. Skipping generation.",
            path
        );
        return Ok(());
    }

    println!("Generating {} synthetic product records...", num_records);
    if let Some(parent) = Path::new(path).parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(path)?;
    writeln!(file, "name,price")?;

    const BRANDS: &[&str] = &[
        "Apple", "Samsung", "Sony", "Dell", "HP", "Lenovo", "ASUS", "Logitech", 
        "Corsair", "Razer", "Anker", "Bose", "Nintendo", "Microsoft", "LG", "Google"
    ];
    const TYPES: &[&str] = &[
        "Smartphone", "Laptop", "Tablet", "Smartwatch", "Earbuds", "Headphones", 
        "Mouse", "Keyboard", "SSD", "Power Bank", "Monitor", "Webcam", "Speaker", "Camera"
    ];
    const MODIFIERS: &[&str] = &[
        "Pro", "Air", "Ultra", "Max", "Plus", "Elite", "Wireless", "RGB", 
        "Portable", "Compact", "Gen 2", "ANC", "4K", "OLED", "Mechanical", "Gaming"
    ];

    let mut names = std::collections::HashSet::new();
    let mut rng = rand::thread_rng();

    while names.len() < num_records {
        let brand = BRANDS[rng.gen_range(0..BRANDS.len())];
        let p_type = TYPES[rng.gen_range(0..TYPES.len())];
        let modifier1 = MODIFIERS[rng.gen_range(0..MODIFIERS.len())];
        let modifier2 = MODIFIERS[rng.gen_range(0..MODIFIERS.len())];
        
        let name = if modifier1 == modifier2 {
            format!("{} {} {}", brand, p_type, modifier1)
        } else {
            format!("{} {} {} {}", brand, p_type, modifier1, modifier2)
        };
        
        if names.insert(name.clone()) {
            // Assign realistic prices based on product type to keep it meaningful
            let price = match p_type {
                "Laptop" => rng.gen_range(599..2499),
                "Smartphone" => rng.gen_range(399..1299),
                "Monitor" => rng.gen_range(199..899),
                "Tablet" => rng.gen_range(199..799),
                "Headphones" | "Earbuds" | "Camera" => rng.gen_range(99..499),
                "Keyboard" | "Mouse" | "SSD" | "Speaker" | "Power Bank" | "Webcam" | "Smartwatch" => rng.gen_range(29..249),
                _ => rng.gen_range(10..1000),
            };
            writeln!(file, "{},{}", name, price)?;
        }
    }

    println!("Dataset generated successfully at '{}'.", path);
    Ok(())
}

/// Reads synthetic dataset from CSV.
fn read_synthetic_data(path: &str) -> Result<Vec<ProductRecord>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_csv_generation_and_reading() {
        let test_path = "data/product_prices_test.csv";
        let _ = fs::remove_file(test_path);

        // Test generation
        generate_synthetic_data(test_path, 10).expect("Failed to generate test synthetic data");
        assert!(Path::new(test_path).exists());

        // Test reading
        let records = read_synthetic_data(test_path).expect("Failed to read test synthetic data");
        assert_eq!(records.len(), 10);
        assert!(!records[0].name.is_empty());
        assert!(records[0].price >= 10 && records[0].price <= 3000);

        // Clean up test file
        let _ = fs::remove_file(test_path);
    }
}
