mod db;

use axum::{http::StatusCode, routing::post, Json, Router};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    // 1. Initialize SQLite database
    if let Err(e) = db::init_db() {
        eprintln!("Failed to initialize database: {}", e);
        std::process::exit(1);
    }
    println!("Database initialized successfully.");

    // 2. Configure Axum Router
    let app = Router::new()
        .route("/api/reset", post(handle_reset))
        .route("/api/upload", post(handle_upload))
        .route("/api/homomorphic-sum", post(handle_homomorphic_sum));

    // 3. Start Tokio Listener
    let addr = "127.0.0.1:8000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Cloud Server listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

// --- API Request / Response Structs ---

#[derive(Serialize)]
struct GenericResponse {
    status: String,
    message: String,
}

#[derive(Deserialize)]
struct UploadRequest {
    public_key_n: String,
    products: Vec<EncryptedProductInput>,
}

#[derive(Deserialize)]
struct EncryptedProductInput {
    name: String,
    encrypted_price: String,
}

#[derive(Serialize)]
struct SumResponse {
    status: String,
    encrypted_sum: String,
}

use axum::response::IntoResponse;

// --- Endpoint Handlers ---

/// Clears all encrypted products and saved configurations.
async fn handle_reset() -> impl IntoResponse {
    match db::reset_db() {
        Ok(_) => (
            StatusCode::OK,
            Json(GenericResponse {
                status: "success".to_string(),
                message: "Database reset successful.".to_string(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenericResponse {
                status: "error".to_string(),
                message: format!("Failed to reset database: {}", e),
            }),
        ),
    }
}

/// Receives public key n and encrypted products, storing them securely in SQLite.
async fn handle_upload(Json(payload): Json<UploadRequest>) -> impl IntoResponse {
    // Verify the public key string can be parsed as a BigUint
    if BigUint::from_str(&payload.public_key_n).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(GenericResponse {
                status: "error".to_string(),
                message: "Invalid public_key_n format. Must be a decimal integer string."
                    .to_string(),
            }),
        );
    }

    // Save public key
    if let Err(e) = db::set_public_key_n(&payload.public_key_n) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenericResponse {
                status: "error".to_string(),
                message: format!("Failed to save public key: {}", e),
            }),
        );
    }

    // Map to tuples for database insertion
    let db_products: Vec<(String, String)> = payload
        .products
        .into_iter()
        .map(|p| (p.name, p.encrypted_price))
        .collect();

    match db::insert_products(&db_products) {
        Ok(_) => (
            StatusCode::OK,
            Json(GenericResponse {
                status: "success".to_string(),
                message: format!(
                    "Successfully stored {} encrypted products.",
                    db_products.len()
                ),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenericResponse {
                status: "error".to_string(),
                message: format!("Database insertion failed: {}", e),
            }),
        ),
    }
}

/// Fetches all stored ciphertexts, retrieves public key n, and aggregates them homomorphically.
async fn handle_homomorphic_sum() -> impl IntoResponse {
    // Get public key n from configuration table
    let pk_n_str = match db::get_public_key_n() {
        Ok(Some(n)) => n,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Public key n has not been uploaded. Please upload products first."
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Database error retrieving public key: {}", e)
                })),
            )
                .into_response();
        }
    };

    let pk_n = BigUint::from_str(&pk_n_str).unwrap();

    // Fetch all encrypted prices
    let enc_price_strings = match db::get_encrypted_prices() {
        Ok(prices) => prices,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Database error retrieving encrypted prices: {}", e)
                })),
            )
                .into_response();
        }
    };

    if enc_price_strings.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "No encrypted products stored. Please upload products first."
            })),
        )
            .into_response();
    }

    // Parse encrypted prices to BigUint
    let mut ciphertexts = Vec::with_capacity(enc_price_strings.len());
    for s in enc_price_strings {
        match BigUint::from_str(&s) {
            Ok(c) => ciphertexts.push(c),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "status": "error",
                        "message": format!("Database contains invalid ciphertext string '{}': {}", s, e)
                    })),
                ).into_response();
            }
        }
    }

    // Execute zero-knowledge homomorphic summation
    let encrypted_sum = paillier_crypto::homomorphic_sum(&ciphertexts, &pk_n);

    (
        StatusCode::OK,
        Json(SumResponse {
            status: "success".to_string(),
            encrypted_sum: encrypted_sum.to_string(),
        }),
    )
        .into_response()
}
