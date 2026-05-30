mod db;

use axum::{http::StatusCode, routing::post, Json, Router};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub fn create_app() -> Router {
    Router::new()
        .route("/", axum::routing::get(serve_html))
        .route("/index.css", axum::routing::get(serve_css))
        .route("/app.js", axum::routing::get(serve_js))
        .route("/api/reset", post(handle_reset))
        .route("/api/upload", post(handle_upload))
        .route("/api/homomorphic-sum", post(handle_homomorphic_sum))
        .route("/api/products", axum::routing::get(handle_get_products))
        .route("/api/public-key", axum::routing::get(handle_get_public_key))
}

#[tokio::main]
async fn main() {
    // 1. Initialize SQLite database
    if let Err(e) = db::init_db() {
        eprintln!("Failed to initialize database: {}", e);
        std::process::exit(1);
    }
    println!("Database initialized successfully.");

    // 2. Configure Axum Router
    let app = create_app();

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

const INDEX_HTML: &str = include_str!("static/index.html");
const INDEX_CSS: &str = include_str!("static/index.css");
const APP_JS: &str = include_str!("static/app.js");

async fn serve_html() -> impl IntoResponse {
    axum::response::Html(INDEX_HTML)
}

async fn serve_css() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        INDEX_CSS,
    )
}

async fn serve_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn handle_get_products() -> impl IntoResponse {
    match db::get_products() {
        Ok(products) => (
            StatusCode::OK,
            Json(products),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenericResponse {
                status: "error".to_string(),
                message: format!("Failed to retrieve products: {}", e),
            }),
        ).into_response(),
    }
}

async fn handle_get_public_key() -> impl IntoResponse {
    match db::get_public_key_n() {
        Ok(Some(n)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "public_key_n": n,
            })),
        ).into_response(),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "public_key_n": null,
            })),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenericResponse {
                status: "error".to_string(),
                message: format!("Failed to retrieve public key: {}", e),
            }),
        ).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use axum::http::StatusCode;
    use std::fs;

    // Use a helper to clean/init db for testing
    fn setup_db() {
        let _ = fs::remove_file("cloud_db_test.sqlite");
        db::init_db().expect("Failed to init test db");
    }

    fn teardown_db() {
        let _ = fs::remove_file("cloud_db_test.sqlite");
    }

    #[tokio::test]
    async fn test_handle_reset() {
        let _lock = db::TEST_MUTEX.lock().unwrap();
        setup_db();
        // Insert a dummy key to verify it is deleted by reset
        db::set_public_key_n("111").unwrap();

        let response = handle_reset().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify it was actually reset
        let pk = db::get_public_key_n().unwrap();
        assert!(pk.is_none());
        teardown_db();
    }

    #[tokio::test]
    async fn test_handle_upload_invalid_key() {
        let _lock = db::TEST_MUTEX.lock().unwrap();
        setup_db();
        let payload = UploadRequest {
            public_key_n: "abc_not_a_number".to_string(),
            products: vec![],
        };
        let response = handle_upload(Json(payload)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        teardown_db();
    }

    #[tokio::test]
    async fn test_handle_upload_and_sum() {
        let _lock = db::TEST_MUTEX.lock().unwrap();
        setup_db();

        // 1. Generate keys from paillier-crypto to have valid mathematical ciphertexts
        let (pk, sk) = paillier_crypto::generate_keys(128);

        // Encrypt some prices
        let c1 = pk.encrypt(&BigUint::from(100u32)).unwrap();
        let c2 = pk.encrypt(&BigUint::from(250u32)).unwrap();

        let payload = UploadRequest {
            public_key_n: pk.n().to_string(),
            products: vec![
                EncryptedProductInput {
                    name: "Item 1".to_string(),
                    encrypted_price: c1.to_string(),
                },
                EncryptedProductInput {
                    name: "Item 2".to_string(),
                    encrypted_price: c2.to_string(),
                },
            ],
        };

        // 2. Upload products
        let upload_res = handle_upload(Json(payload)).await.into_response();
        assert_eq!(upload_res.status(), StatusCode::OK);

        // 3. Compute homomorphic sum
        let sum_res = handle_homomorphic_sum().await.into_response();
        assert_eq!(sum_res.status(), StatusCode::OK);

        // Read body to verify correctness
        let body_bytes = axum::body::to_bytes(sum_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(body_json["status"], "success");
        let enc_sum_str = body_json["encrypted_sum"].as_str().unwrap();
        let enc_sum = BigUint::from_str(enc_sum_str).unwrap();

        // Decrypt sum
        let dec_sum = sk.decrypt(&enc_sum).unwrap();
        assert_eq!(dec_sum, BigUint::from(350u32));

        teardown_db();
    }
}
