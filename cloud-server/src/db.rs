use rusqlite::{params, Connection, Result};

#[cfg(test)]
const DB_PATH: &str = "cloud_db_test.sqlite";
#[cfg(not(test))]
const DB_PATH: &str = "cloud_db.sqlite";

#[cfg(test)]
pub static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Initializes the SQLite database and creates the necessary tables if they don't exist.
pub fn init_db() -> Result<()> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS encrypted_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            encrypted_price TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS server_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Truncates the database by deleting all records from the tables.
pub fn reset_db() -> Result<()> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute("DELETE FROM encrypted_products", [])?;
    conn.execute("DELETE FROM server_config", [])?;
    // Reset autoincrement sequence
    let _ = conn.execute(
        "DELETE FROM sqlite_sequence WHERE name='encrypted_products'",
        [],
    );
    Ok(())
}

/// Inserts a batch of products into the database.
pub fn insert_products(products: &[(String, String)]) -> Result<()> {
    let mut conn = Connection::open(DB_PATH)?;
    let tx = conn.transaction()?;
    {
        let mut stmt =
            tx.prepare("INSERT INTO encrypted_products (name, encrypted_price) VALUES (?1, ?2)")?;
        for (name, enc_price) in products {
            stmt.execute(params![name, enc_price])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Retrieves all encrypted prices from the database.
pub fn get_encrypted_prices() -> Result<Vec<String>> {
    let conn = Connection::open(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT encrypted_price FROM encrypted_products")?;
    let price_iter = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut prices = Vec::new();
    for price in price_iter {
        prices.push(price?);
    }
    Ok(prices)
}

/// Saves the public key `n` to the server configuration.
pub fn set_public_key_n(n: &str) -> Result<()> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute(
        "INSERT OR REPLACE INTO server_config (key, value) VALUES ('public_key_n', ?1)",
        params![n],
    )?;
    Ok(())
}

/// Retrieves the stored public key `n` from the server configuration.
pub fn get_public_key_n() -> Result<Option<String>> {
    let conn = Connection::open(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT value FROM server_config WHERE key = 'public_key_n'")?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get::<_, String>(0)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_all_db_operations() {
        let _lock = TEST_MUTEX.lock().unwrap();
        // Ensure clean slate by deleting test db if it exists
        let _ = fs::remove_file(DB_PATH);

        // 1. Test init_db
        init_db().expect("Failed to initialize database");
        assert!(std::path::Path::new(DB_PATH).exists(), "DB file was not created");

        // 2. Test get_public_key_n on empty db
        let pk = get_public_key_n().expect("Failed to get public key");
        assert!(pk.is_none(), "Public key should be None initially");

        // 3. Test set_public_key_n and get_public_key_n
        set_public_key_n("1234567890").expect("Failed to set public key");
        let pk = get_public_key_n().expect("Failed to get public key");
        assert_eq!(pk, Some("1234567890".to_string()));

        // 4. Test get_encrypted_prices on empty db
        let prices = get_encrypted_prices().expect("Failed to get prices");
        assert!(prices.is_empty(), "Prices list should be empty initially");

        // 5. Test insert_products and get_encrypted_prices
        let products = vec![
            ("Product A".to_string(), "999999".to_string()),
            ("Product B".to_string(), "888888".to_string()),
        ];
        insert_products(&products).expect("Failed to insert products");
        let prices = get_encrypted_prices().expect("Failed to get prices");
        assert_eq!(prices.len(), 2);
        assert_eq!(prices[0], "999999");
        assert_eq!(prices[1], "888888");

        // 6. Test reset_db
        reset_db().expect("Failed to reset database");
        let pk_after = get_public_key_n().expect("Failed to get public key");
        assert!(pk_after.is_none(), "Public key should be None after reset");
        let prices_after = get_encrypted_prices().expect("Failed to get prices");
        assert!(prices_after.is_empty(), "Prices list should be empty after reset");

        // Clean up test file after test run
        let _ = fs::remove_file(DB_PATH);
    }
}
