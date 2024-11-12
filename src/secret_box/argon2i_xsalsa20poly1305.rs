use argon2::{self, password_hash::SaltString, Argon2, ParamsBuilder, PasswordHasher};
use generic_array::GenericArray;
use xsalsa20poly1305::{XSalsa20Poly1305, KeyInit, aead::Aead};

use super::{SecretBoxJson, FromReprError, Bs58Error, DecryptError, EncryptError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretBoxArgon2iXsalsa20poly1305 {
    pub nonce: [u8; 24],
    pub pwsalt: SaltString,
    pw_mem_limit_bytes: i64,
    pw_ops_limit: u32,
    ciphertext: Vec<u8>,
}

const SECRET_BOX_PRIMITIVE: &str = "xsalsa20poly1305";
const PASSWORD_HASH_PRIMITIVE: &str = "argon2i";
const VERSION_CHECK_BYTE: u8 = 0x02;

impl SecretBoxArgon2iXsalsa20poly1305 {
    pub fn try_from_repr(repr: SecretBoxJson) -> Result<Self, FromReprError> {
        let box_primitive = repr.box_primitive;
        let pw_primitive = repr.pw_primitive;
        if box_primitive != SECRET_BOX_PRIMITIVE || pw_primitive != PASSWORD_HASH_PRIMITIVE {
            return Err(FromReprError::BadAlgorithm {
                box_primitive,
                pw_primitive,
            });
        }

        fn base58_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, Bs58Error> {
            let mut v = bs58::decode(input)
                .with_check(Some(VERSION_CHECK_BYTE))
                .into_vec()?;
            // Remove version byte
            v.remove(0);
            Ok(v)
        }

        Ok(SecretBoxArgon2iXsalsa20poly1305 {
            nonce: base58_decode(&repr.nonce)
                .map_err(FromReprError::Nonce)?
                .try_into()
                .unwrap(),
            pwsalt: {
                let pwsalt_bytes = base58_decode(&repr.pwsalt).map_err(FromReprError::Salt)?;
                SaltString::encode_b64(pwsalt_bytes.as_slice())
                    .map_err(FromReprError::SaltLength)?
            },
            pw_mem_limit_bytes: repr.pwdiff[0],
            pw_ops_limit: repr.pwdiff[1] as u32,
            ciphertext: base58_decode(&repr.ciphertext).map_err(FromReprError::CipherText)?,
        })
    }

    pub fn to_repr(&self) -> SecretBoxJson {
        fn base58_encode(input: impl AsRef<[u8]>) -> String {
            bs58::encode(input)
                .with_check_version(VERSION_CHECK_BYTE)
                .into_string()
        }

        let pwsalt = {
            // 16 is sufficient here
            let mut buf = [0; 16];
            let bytes = self.pwsalt.decode_b64(&mut buf).unwrap();
            base58_encode(bytes)
        };

        SecretBoxJson {
            box_primitive: SECRET_BOX_PRIMITIVE.to_string(),
            pw_primitive: PASSWORD_HASH_PRIMITIVE.to_string(),
            nonce: base58_encode(&self.nonce),
            pwsalt,
            pwdiff: [self.pw_mem_limit_bytes, self.pw_ops_limit as i64],
            ciphertext: base58_encode(&self.ciphertext),
        }
    }

    fn hasher(
        pw_mem_limit_bytes: i64,
        pw_ops_limit: u32,
    ) -> Result<Argon2<'static>, argon2::Error> {
        let mut param_builder = ParamsBuilder::new();
        param_builder.m_cost((pw_mem_limit_bytes / 1024) as u32);
        param_builder.t_cost(pw_ops_limit);
        Ok(Argon2::new(
            argon2::Algorithm::Argon2i,
            argon2::Version::V0x13,
            param_builder.build()?,
        ))
    }

    pub fn encrypt(
        nonce: [u8; 24],
        pwsalt: SaltString,
        mut plaintext: Vec<u8>,
        password: &[u8],
    ) -> Result<Self, EncryptError> {
        let pw_mem_limit_bytes = 134217728;
        let pw_ops_limit = 6;

        let hasher =
            Self::hasher(pw_mem_limit_bytes, pw_ops_limit).map_err(EncryptError::Argon2)?;

        let hash = hasher
            .hash_password(password, &pwsalt)
            .map_err(EncryptError::Hash)?
            .hash
            .expect("must not fail");

        let key = GenericArray::from_slice(hash.as_bytes());
        let cipher = XSalsa20Poly1305::new(key);
        plaintext.insert(0, 1);
        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext.as_slice())
            .map_err(EncryptError::XSalsa20Poly1305)?;

        Ok(SecretBoxArgon2iXsalsa20poly1305 {
            nonce,
            pwsalt,
            pw_mem_limit_bytes,
            pw_ops_limit,
            ciphertext,
        })
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let hasher = Self::hasher(self.pw_mem_limit_bytes, self.pw_ops_limit)
            .map_err(DecryptError::Argon2)?;

        let hash = hasher
            .hash_password(password, &self.pwsalt)
            .map_err(DecryptError::Hash)?
            .hash
            .expect("must not fail");

        let key = GenericArray::from_slice(hash.as_bytes());
        let cipher = XSalsa20Poly1305::new(key);
        let mut bytes = cipher
            .decrypt(
                GenericArray::from_slice(self.nonce.as_slice()),
                self.ciphertext.as_ref(),
            )
            .map_err(DecryptError::XSalsa20Poly1305)?;
        bytes.remove(0);

        Ok(bytes)
    }
}
