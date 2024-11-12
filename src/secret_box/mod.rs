mod argon2i_xsalsa20poly1305;
pub use self::argon2i_xsalsa20poly1305::SecretBoxArgon2iXsalsa20poly1305;

use serde::{Serialize, Deserialize};

use thiserror::Error;

use bs58::decode::Error as Bs58Error;

/// Json representation of the wallet file
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SecretBoxJson {
    pub box_primitive: String,
    pub pw_primitive: String,
    pub nonce: String,
    pub pwsalt: String,
    pub pwdiff: [i64; 2],
    pub ciphertext: String,
}

#[derive(Debug, Error)]
pub enum FromReprError {
    #[error("must use {box_primitive} and {pw_primitive}")]
    BadAlgorithm {
        box_primitive: String,
        pw_primitive: String,
    },
    #[error("bad nonce: {0}")]
    Nonce(Bs58Error),
    #[error("bad cipher text: {0}")]
    CipherText(Bs58Error),
    #[error("bad salt: {0}")]
    Salt(Bs58Error),
    #[error("bad salt length: {0}")]
    SaltLength(argon2::password_hash::Error),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("argon2i: {0}")]
    Argon2(argon2::Error),
    #[error("argon2i hash: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("xsalsa20poly1305: {0}")]
    XSalsa20Poly1305(xsalsa20poly1305::Error),
}

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("argon2i: {0}")]
    Argon2(argon2::Error),
    #[error("argon2i hash: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("xsalsa20poly1305: {0}")]
    XSalsa20Poly1305(xsalsa20poly1305::Error),
}
