# LTHS Cybersecurity DIY Cipher

The cypher I made for my cybersecurity class in our encryption unit.

## Building

For most people, attached binaries will be sufficient. If you want to build from source, you will need to have the Rust programming language installed. You can install it from [rustup.rs](https://rustup.rs/). Clone the directory and run `cargo build --release` to build the binary.

## How to use

The program is a command line tool. Run `lths_cybersecurity_diy_cypher --help` for usage information.

Generally, a key and input file must be specified with the `-k` and `-i` flags, respectively. The output file can be specified with the `-o` flag, and the key size can be specified with the `-s` flag, and be one of `256`, `384`, or `512`. The program will encrypt the input file and write the result to the output file.

## How it works

Currently, the cypher works like this:

1. The key is hashed with `blake3` to produce a 256-, 384-, or 512-bit key to create the master key.
2. The input file is read in blocks of 32, 48, or 64 bytes (depending on key size).
3. Each block generates it's own key by XORing the master key with the block index and hashing with `blake3`.
4. This is the start of the rounds. Each round generates it's own key by XORing the block key with the round index and hashing with `blake3`
5. Each chunk is XORed with the key.
6. The chunk shifted right by 1 bit + the round number + the offest from the starting chunk
7. Steps 4-6 repeat for a total of 14, 16, or 18 rounds (depending on key size).
8. The result is written to the output file.

Decryption works by reversing the steps.
