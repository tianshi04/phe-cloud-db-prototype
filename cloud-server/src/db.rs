use rusqlite::{params, Connection, Result};

const DB_PATH: &str = "cloud_db.sqlite";

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
