use argon2::password_hash::SaltString;
use proof_systems::mina_signer::Keypair;

use crate::{SecretBoxJson, SecretBoxArgon2iXsalsa20poly1305};

#[test]
fn basic() {
    const WALLET: &str = r#"{"box_primitive":"xsalsa20poly1305","pw_primitive":"argon2i","nonce":"7fZcNVSjcV2s9fa3mW1WFEVDtTFbqAqncwbEtCH","pwsalt":"8KATgNU1eDy7x542QX9trxfkWFmi","pwdiff":[134217728,6],"ciphertext":"Ex334M3ogG7a3xXhr4EqbePoV4kn1jzM2xRfcxThunviEjsZmRMTPUmv2wQSA6FrdkgpG5QWM"}"#;
    const WALLET_PUB: &str = r#"B62qjEPouxe5E8zPXYkfQqakNYbmS2RF5B6SZatyh1a3kWv8cgV3afh"#;

    let wallet_repr = serde_json::from_str::<SecretBoxJson>(WALLET).unwrap();
    let wallet = SecretBoxArgon2iXsalsa20poly1305::try_from_repr(wallet_repr.clone()).unwrap();
    let mut bytes = wallet.decrypt(b"").unwrap();

    let wallet_prime = SecretBoxArgon2iXsalsa20poly1305::encrypt(
        wallet.nonce.clone(),
        wallet.pwsalt.clone(),
        bytes.clone(),
        &[],
    )
    .unwrap();
    let wallet_repr_prime = wallet_prime.to_repr();
    assert_eq!(wallet_repr_prime, wallet_repr);

    bytes.reverse();

    let pair = Keypair::from_hex(&hex::encode(&bytes)).unwrap();
    assert_eq!(pair.get_address(), WALLET_PUB);
}

#[test]
fn special() {
    use tiny_hderive::bip32::ExtendedPrivKey;
    use bip39::{Mnemonic, Language, Seed};

    let mn = Mnemonic::from_phrase(
        "screen august auto cabbage coil combine dumb pretty cliff robust mail embrace",
        Language::English,
    )
    .unwrap();

    let seed = Seed::new(&mn, "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), r#"m/44'/12586'/0'/0/0"#).unwrap();
    let mut key = ext.secret();
    key[0] &= 0x3f;

    let pair = Keypair::from_hex(&hex::encode(&key)).unwrap();
    assert_eq!(
        "B62qpuQTjJQbhCjRhxNrUA5jnorovcmMgnH9DeZgXdhfNJxG7tun9Rw",
        pair.get_address()
    );

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
