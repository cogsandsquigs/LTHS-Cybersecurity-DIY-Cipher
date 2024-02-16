mod cli;
mod tests;

use blake3::Hasher;
use clap::Parser;
use cli::{Action, Args, KeySize};
use std::io::Read;

/// The S-Box and its inverse for the AES algorithm as (sbox, inverse_sbox).
const SBOX_TUPLES: ([u8; 256], [u8; 256]) = initialize_aes_sbox();

fn main() {
    let args = Args::parse();

    let mut file = std::fs::File::open(&args.input_file).unwrap();
    let mut input = Vec::new();
    file.read_to_end(&mut input).unwrap();

    let key = args.key.as_bytes();

    let output = match args.action {
        Action::Encrypt => {
            println!(
                "Encrypting file '{}' and outputing to '{}'...",
                args.input_file.display(),
                args.output_file.display()
            );

            encrypt(key, &input, args.key_size)
        }
        Action::Decrypt => {
            println!(
                "Decrypting file '{}' and outputing to '{}'...",
                args.input_file.display(),
                args.output_file.display()
            );

            decrypt(key, &input, args.key_size)
        }
    };

    // Send output to file
    std::fs::write(&args.output_file, output).unwrap(); // TODO: Handle error

    println!("Done!");
}

/// Encrypts the input with the given key and key size
fn encrypt(key: &[u8], input: &[u8], key_size: KeySize) -> Vec<u8> {
    let (block_size, rounds, mut input, block_keys) = prepare_input(key, input, key_size);

    for (block_idx, (block, block_keys)) in input.iter_mut().zip(block_keys).enumerate() {
        // Get the round keys for this block. Note that they are offset by XORing with the block index.
        let round_keys = derive_subkeys(block_keys, block_size, rounds, block_idx);

        for (round_idx, round_key) in round_keys.iter().enumerate() {
            // Substitute each byte with the S-Box
            for byte in block.iter_mut() {
                *byte = SBOX_TUPLES.0[*byte as usize];
            }

            *block = xor(block, round_key); // XOR the block with the round key
            block.rotate_left((block_idx + round_idx) % block_size) // Rotate the block left by the block index to confuse the output
        }
    }

    input.concat()
}

/// Encrypts the input with the given key and key size
fn decrypt(key: &[u8], input: &[u8], key_size: KeySize) -> Vec<u8> {
    let (block_size, rounds, mut input, block_keys) = prepare_input(key, input, key_size);

    for (block_idx, (block, block_key)) in input.iter_mut().zip(block_keys).enumerate() {
        // Get the round keys for this block. Note that they are offset by XORing with the block index.
        let round_keys = derive_subkeys(block_key, block_size, rounds, block_idx);

        for (round_idx, round_key) in round_keys.iter().enumerate().rev() {
            // Undo the steps in reverse order

            block.rotate_right((block_idx + round_idx) % block_size); // Undo the rotation
            *block = xor(block, round_key); // XOR the block with the round key

            // Substitute each byte with the inverse S-Box
            for byte in block.iter_mut() {
                *byte = SBOX_TUPLES.1[*byte as usize];
            }
        }
    }

    let mut output = input.concat();

    // Remove any padding/null bytes at the end
    while output.last() == Some(&0) {
        output.pop();
    }

    output
}

/// From the input, it returns, in order: The block size, the number of rounds, the input split into blocks, and the block keys.
fn prepare_input(
    key: &[u8],
    input: &[u8],
    key_size: KeySize,
) -> (usize, usize, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let block_size = key_size.block_size();
    let rounds = key_size.rounds();

    let input: Vec<Vec<u8>> = input
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

    let master_key: Vec<u8> = get_master_key(key, key_size); // The master key is the hash of the input key
    let block_keys = derive_subkeys(master_key, block_size, input.len(), 0); // One key for each block

    (block_size, rounds, input, block_keys)
}

// Gets the master key by hashing the input key with blake3 at sizes 256, 384, and 512 bits
fn get_master_key(key: &[u8], key_size: KeySize) -> Vec<u8> {
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

// Derives the subkeys from the master key via blake3 at sizes 256, 384, and 512 bits
fn derive_subkeys(
    master_key: Vec<u8>,
    block_size: usize,
    count: usize,
    offset: usize,
) -> Vec<Vec<u8>> {
    // Get the offset bytes as the little-endian representation of the offset, padded with 0s on the right
    // to the block size.
    let mut offset_bytes = offset.to_le_bytes().to_vec();
    offset_bytes.resize(block_size, 0);

    let initial_key = xor(&master_key, &offset_bytes);
    let mut subkeys = vec![initial_key];

    // The first subkey is not the master key, but derived from it.
    for i in 1..count {
        let mut hasher = Hasher::new();
        let mut subkey = vec![0_u8; block_size];

        hasher
            .update(&subkeys[i - 1])
            .finalize_xof()
            .read_exact(&mut subkey)
            .unwrap(); // TODO: Handle error

        subkeys.push(subkey);
    }

    subkeys
}

/// XORs two byte arrays together. If the arrays are different lengths, the output will be the length
/// of the shorter array.
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

/// Initializes the AES S-Box and its inverse as (sbox, inverse_sbox).
const fn initialize_aes_sbox() -> ([u8; 256], [u8; 256]) {
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    let mut sbox = [0; 256];
    let mut inverse_sbox = [0; 256];

    loop {
        // Multiply p by 3
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1B } else { 0 });

        // Divide q by 3 (equals multiplication by 0xf6)
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 0x80 != 0 { 0x09 } else { 0 };

        // Compute the affine transformation
        let xformed = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = xformed ^ 0x63;

        // Compute the inverse S-Box
        inverse_sbox[sbox[p as usize] as usize] = p;

        // loop invariant: p * q == 1 in the Galois field
        if p == 1 {
            break;
        }
    }

    // 0 is a special case since it has no inverse
    sbox[0] = 0x63;
    inverse_sbox[0x63] = 0;

    (sbox, inverse_sbox)
}
