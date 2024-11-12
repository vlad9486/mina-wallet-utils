use std::io;

use argon2::password_hash::SaltString;
use mina_wallet_utils::SecretBoxArgon2iXsalsa20poly1305;
use proof_systems::mina_signer::Keypair;
use tiny_hderive::bip32::ExtendedPrivKey;
use bip39::{Mnemonic, Language, Seed};

fn main() {
    let mut phrase = String::new();
    io::stdin().read_line(&mut phrase).unwrap();

    let mn = Mnemonic::from_phrase(&phrase, Language::English).unwrap();

    let seed = Seed::new(&mn, "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), r#"m/44'/12586'/0'/0/0"#).unwrap();
    let mut key = ext.secret();
    key[0] &= 0x3f;

    let pair = Keypair::from_hex(&hex::encode(&key)).unwrap();
    println!("{}", pair.get_address());

    key.reverse();

    let wallet_prime = SecretBoxArgon2iXsalsa20poly1305::encrypt(
        rand::random(),
        SaltString::generate(rand::thread_rng()),
        key.to_vec(),
        &[],
    )
    .unwrap();
    let wallet_repr_prime = wallet_prime.to_repr();
    println!("{}", serde_json::to_string(&wallet_repr_prime).unwrap());
}
