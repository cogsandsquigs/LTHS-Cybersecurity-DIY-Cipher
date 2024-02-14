mod cli;

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

    // Convert the input to 16-byte blocks and key to a byte array
    let key = key.as_bytes();
    let input: Vec<Vec<u8>> = input
        .as_bytes()
        .chunks(16)
        .map(|chunk| {
            if chunk.len() == 16 {
                chunk.to_vec()
            } else {
                let mut new_chunk = chunk.to_vec();
                new_chunk.resize(16, 0);
                new_chunk
            }
        })
        .collect();

    println!("Key: {:?}", key);
    println!("Input: {:?}", input);
}
