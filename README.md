# LTHS Cybersecurity DIY Cipher

The cypher I made for my cybersecurity class in our encryption unit.

## Building

For most people, attached binaries will be sufficient. If you want to build from source, you will need to have the Rust programming language installed. You can install it from [rustup.rs](https://rustup.rs/). Clone the directory and run `cargo build --release` to build the binary.

## How to use

The program is a command line tool. Run `lths_cybersecurity_diy_cypher --help` for usage information. Generally, a key and input file must be specified with the `-k` and `-i` flags, respectively. The output file can be specified with the `-o` flag, and the key size can be specified with the `-s` flag, and be one of `256`, `384`, or `512`. The program will encrypt the input file and write the result to the output file.
