mod cli;

use std::io::Read;

use blake3::Hasher;
use clap::Parser;
use cli::{Action, Args, KeySize};

fn main() {
    let args = Args::parse();

    match args.action {
        Action::Encrypt { input } => encrypt(args.key, input, args.key_size),
        Action::Decrypt {} => todo!(),
    }
}

fn encrypt(key: String, input: String, key_size: KeySize) {
    println!("Encrypting input with a {}-bit key", key_size as u16);

    let block_size = key_size.block_size();
    let rounds = key_size.rounds();
    let master_key = get_master_key(key, key_size);
    let round_keys = derive_subkeys(master_key, key_size);
    let mut input: Vec<Vec<u8>> = input
        .as_bytes()
        .chunks(block_size)
        // TODO: Only call this at the ending block if it's not the correct size, because only that block
        // will need to be padded.
        .map(|chunk| {
            // If the block size is correct, use the chunk as is.
            if chunk.len() == block_size {
                chunk.to_vec()
            }
            // Otherwise, pad it with 0s
            else {
                let mut new_chunk = chunk.to_vec();
                new_chunk.resize(block_size, 0);
                new_chunk
            }
        })
        .collect();

    println!("Input: {:?}", input);

    for round_key in round_keys {
        for block in input.iter_mut() {
            *block = xor(block, &round_key);
        }
    }

    println!("Output: {:?}", input);
}

// Gets the master key by hashing the input key with blake3 at sizes 256, 384, and 512 bits
fn get_master_key(key: String, key_size: KeySize) -> Vec<u8> {
    let key = key.as_bytes();
    let mut hasher = Hasher::new();
    let mut master_key = vec![0_u8; key_size.block_size()];

    // Hash the key with blake3
    hasher
        .update(key)
        .finalize_xof()
        .read_exact(&mut master_key)
        .unwrap(); // TODO: Handle error

    master_key
}

// Derives the subkeys from the master key
fn derive_subkeys(master_key: Vec<u8>, key_size: KeySize) -> Vec<Vec<u8>> {
    let block_size = key_size.block_size();
    let rounds = key_size.rounds();
    let mut subkeys = vec![];
    let mut prev_subkey = master_key;

    // The first subkey is not the master key, but derived from it.
    for _ in 0..rounds {
        let mut hasher = Hasher::new();
        let mut subkey = vec![0_u8; block_size];

        hasher
            .update(&prev_subkey)
            .finalize_xof()
            .read_exact(&mut subkey)
            .unwrap(); // TODO: Handle error

        prev_subkey = subkey.clone(); // TODO: Remove clone for efficiency
        subkeys.push(subkey);
    }

    subkeys
}

/// XORs two byte arrays together
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}
