use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use themis::{
    keys::{EcdsaPrivateKey, EcdsaPublicKey, KeyPair},
    secure_cell::SecureCell,
    secure_message::SecureMessage,
};

const KEY_CONTEXT: &str = "<User's private key>";

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

fn hash(input: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut buff = [0; 8];
    hasher.update(input).finalize_xof().fill(&mut buff);
    hex::encode(&buff)
}

#[derive(Clone)]
pub struct PublicKey(EcdsaPublicKey);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = hash(self.0.as_ref());
        f.debug_tuple("PublicKey").field(&hash).finish()
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = hash(self.0.as_ref());
        f.debug_tuple("PrivateKey").field(&hash).finish()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buff: Vec<u8> = Vec::deserialize(deserializer)?;
        let key = EcdsaPublicKey::try_from_slice(&buff).map_err(serde::de::Error::custom)?;
        Ok(Self(key))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

#[derive(Clone)]
pub struct PrivateKey(EcdsaPrivateKey);

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buff: Vec<u8> = Vec::deserialize(deserializer)?;
        let key = EcdsaPrivateKey::try_from_slice(&buff).map_err(serde::de::Error::custom)?;
        // TODO: user proper zeroization
        buff.fill(0);
        Ok(Self(key))
    }
}

fn passphrase(pass: &str) -> String {
    format!("password: {:?}", pass)
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedPrivateKey(Vec<u8>);

impl EncryptedPrivateKey {
    pub fn decrypt(self, pass: &str) -> anyhow::Result<PrivateKey> {
        let cell = SecureCell::with_passphrase(passphrase(pass))?.seal();
        let raw = cell.decrypt_with_context(self.0, KEY_CONTEXT)?;
        let key = EcdsaPrivateKey::try_from_slice(&raw)?;
        Ok(PrivateKey(key))
    }
}

impl PrivateKey {
    pub fn encrypt(self, pass: &str) -> anyhow::Result<EncryptedPrivateKey> {
        let cell = SecureCell::with_passphrase(passphrase(pass))?.seal();
        let raw = cell.encrypt_with_context(&self.0, KEY_CONTEXT)?;
        Ok(EncryptedPrivateKey(raw))
    }
}

pub fn gen_keypair() -> (PrivateKey, PublicKey) {
    let (private, public) = themis::keygen::gen_ec_key_pair().split();
    (PrivateKey(private), PublicKey(public))
}

impl PrivateKey {
    pub fn message_to(&self, rhs: &PublicKey) -> anyhow::Result<SecureMessage> {
        let pair = KeyPair::try_join(self.0.clone(), rhs.0.clone())?;
        Ok(SecureMessage::new(pair))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
