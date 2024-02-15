#![cfg(test)]

use super::*;
use rand::{self, Rng};

/// Generates a random bitstring for testing
fn gen_random_str() -> Vec<u8> {
    let rand_len = rand::thread_rng().gen_range(1..4096);

    let random_bytes: Vec<u8> = (0..rand_len).map(|_| rand::random::<u8>()).collect();

    random_bytes
}

/// Test encryption and decryption of a message with 256 bit key size
#[test]
fn test_encrypt_decrypt_256() {
    let key: Vec<u8> = gen_random_str();
    let input = gen_random_str();
    let key_size = KeySize::Bits256;

    let encrypted = encrypt(&key, &input, key_size);
    let decrypted = decrypt(&key, &encrypted, key_size);

    assert_eq!(input, decrypted.as_slice());
}

/// Test encryption and decryption of a message with 384 bit key size
#[test]
fn test_encrypt_decrypt_384() {
    let key: Vec<u8> = gen_random_str();
    let input = gen_random_str();
    let key_size = KeySize::Bits384;

    let encrypted = encrypt(&key, &input, key_size);
    let decrypted = decrypt(&key, &encrypted, key_size);

    assert_eq!(input, decrypted.as_slice());
}

/// Test encryption and decryption of a message with 384 bit key size
#[test]
fn test_encrypt_decrypt_512() {
    let key: Vec<u8> = gen_random_str();
    let input = gen_random_str();
    let key_size = KeySize::Bits512;

    let encrypted = encrypt(&key, &input, key_size);
    let decrypted = decrypt(&key, &encrypted, key_size);

    assert_eq!(input, decrypted.as_slice());
}
