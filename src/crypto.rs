use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn format_err<T: std::fmt::Display>(err: T) -> anyhow::Error {
    anyhow::anyhow!("{}", err)
}

pub fn new_password_hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(format_err)?;
    Ok(hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> anyhow::Result<()> {
    let hash = PasswordHash::new(hash).map_err(format_err)?;
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &hash)
        .map_err(format_err)
}
