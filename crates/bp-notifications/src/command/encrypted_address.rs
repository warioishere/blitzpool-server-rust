// SPDX-License-Identifier: AGPL-3.0-or-later

//! Addresses sent encrypted with the pool's public key, so they do not stand
//! in a chat in the clear. The dashboard's "Telegram Bot" page and the
//! encryptor script both produce base64 of RSA-OAEP with SHA-256; the bot
//! decrypts it with the matching private key.

use aws_lc_rs::rsa::{OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA256_MGF1SHA256};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivateKeyDer;

/// Shortest text taken for an encrypted address. Ciphertext is as long as
/// the key (2048 bits and up), far past any plain address.
const MIN_ENCRYPTED_LEN: usize = 100;

/// The private key that opens encrypted addresses.
pub struct MessageKey(OaepPrivateDecryptingKey);

/// Why an argument that looks encrypted gave no address.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum EncryptedAddressError {
    /// This pool has no key to open it.
    NoKey,
    /// It is shorter or longer than the key's ciphertext: copied in part.
    /// Carries the length it must have.
    Incomplete { expected_len: usize },
    /// The key does not open it, or it holds no text.
    Unreadable,
}

impl MessageKey {
    /// A PKCS#8 PEM private key (`BEGIN PRIVATE KEY`).
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let der = PrivateKeyDer::from_pem_slice(pem).map_err(|e| e.to_string())?;
        let PrivateKeyDer::Pkcs8(k) = der else {
            return Err(
                "not a PKCS#8 private key; convert it with `openssl pkcs8 -topk8 -nocrypt`"
                    .to_string(),
            );
        };
        let key =
            PrivateDecryptingKey::from_pkcs8(k.secret_pkcs8_der()).map_err(|e| e.to_string())?;
        OaepPrivateDecryptingKey::new(key)
            .map(Self)
            .map_err(|e| e.to_string())
    }

    /// Length of a whole encrypted address in base64: the key's size.
    fn encoded_len(&self) -> usize {
        self.0.key_size_bytes().div_ceil(3) * 4
    }

    fn decrypt(&self, encoded: &str) -> Option<String> {
        let ciphertext = STANDARD.decode(encoded).ok()?;
        let mut plaintext = vec![0u8; self.0.min_output_size()];
        let plain = self
            .0
            .decrypt(&OAEP_SHA256_MGF1SHA256, &ciphertext, &mut plaintext, None)
            .ok()?;
        String::from_utf8(plain.to_vec()).ok()
    }
}

/// Base64 characters, at least [`MIN_ENCRYPTED_LEN`] of them: what an
/// encrypted address looks like, whole or copied in part, and no plain one
/// does.
pub(super) fn looks_encrypted(arg: &str) -> bool {
    arg.len() >= MIN_ENCRYPTED_LEN
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// The address inside an encrypted argument. The encryptor script invites
/// a whole command (`/subscribe bc1q...`), so a leading command is dropped.
pub(super) fn open_encrypted_address(
    key: Option<&MessageKey>,
    arg: &str,
) -> Result<String, EncryptedAddressError> {
    let key = key.ok_or(EncryptedAddressError::NoKey)?;
    let expected_len = key.encoded_len();
    if arg.len() != expected_len {
        return Err(EncryptedAddressError::Incomplete { expected_len });
    }
    let plain = key.decrypt(arg).ok_or(EncryptedAddressError::Unreadable)?;
    let mut tokens = plain.split_whitespace().peekable();
    if tokens.peek().is_some_and(|t| t.starts_with('/')) {
        tokens.next();
    }
    tokens
        .next()
        .map(str::to_string)
        .ok_or(EncryptedAddressError::Unreadable)
}

/// A fresh key and an encryptor for its public half, as the dashboard and
/// the script use it.
#[cfg(test)]
pub(super) fn test_key() -> (MessageKey, impl Fn(&str) -> String) {
    let (pkcs8, encrypt) = tests::key_pair();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(pkcs8)
    );
    (MessageKey::from_pem(pem.as_bytes()).unwrap(), encrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, OaepPublicEncryptingKey, PublicEncryptingKey};

    const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn pem(label: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            STANDARD.encode(der)
        )
    }

    /// A key pair: the private key's PKCS#8 DER and an encryptor with the
    /// public half, as the dashboard and the script use it.
    pub(super) fn key_pair() -> (Vec<u8>, impl Fn(&str) -> String) {
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = private.as_der().unwrap().as_ref().to_vec();
        let public = OaepPublicEncryptingKey::new(
            PublicEncryptingKey::from_der(private.public_key().as_der().unwrap().as_ref()).unwrap(),
        )
        .unwrap();
        let encrypt = move |plain: &str| {
            let mut out = vec![0u8; public.ciphertext_size()];
            let ct = public
                .encrypt(&OAEP_SHA256_MGF1SHA256, plain.as_bytes(), &mut out, None)
                .unwrap();
            STANDARD.encode(ct)
        };
        (pkcs8, encrypt)
    }

    #[test]
    fn an_address_encrypted_with_the_public_key_opens() {
        let (pkcs8, encrypt) = key_pair();
        let key = MessageKey::from_pem(pem("PRIVATE KEY", &pkcs8).as_bytes()).unwrap();
        for plain in [ADDRESS.to_string(), format!("/subscribe {ADDRESS}")] {
            let sent = encrypt(&plain);
            assert!(looks_encrypted(&sent));
            assert_eq!(
                open_encrypted_address(Some(&key), &sent).as_deref(),
                Ok(ADDRESS)
            );
        }
    }

    #[test]
    fn what_cannot_be_opened_says_why() {
        let (pkcs8, encrypt) = key_pair();
        let (_, other) = key_pair();
        let key = MessageKey::from_pem(pem("PRIVATE KEY", &pkcs8).as_bytes()).unwrap();
        let sent = encrypt(ADDRESS);
        assert_eq!(
            open_encrypted_address(None, &sent),
            Err(EncryptedAddressError::NoKey)
        );
        assert_eq!(
            open_encrypted_address(Some(&key), &other(ADDRESS)),
            Err(EncryptedAddressError::Unreadable)
        );
        assert_eq!(
            open_encrypted_address(Some(&key), &encrypt("   ")),
            Err(EncryptedAddressError::Unreadable)
        );
        // Copied in part: the ciphertext of a 2048 bit key is 344 characters.
        let whole = encrypt(ADDRESS);
        assert_eq!(whole.len(), 344);
        let part = &whole[..300];
        assert!(looks_encrypted(part));
        assert_eq!(
            open_encrypted_address(Some(&key), part),
            Err(EncryptedAddressError::Incomplete { expected_len: 344 })
        );
    }

    #[test]
    fn plain_addresses_do_not_look_encrypted() {
        assert!(!looks_encrypted(ADDRESS));
        assert!(!looks_encrypted("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        assert!(!looks_encrypted(&"a-".repeat(60)));
        assert!(looks_encrypted(&"QUJD".repeat(25)));
    }
}
