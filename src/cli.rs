use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Encrypts and decrypts a string using my own DIY cipher
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Action to take
    #[command(subcommand)]
    pub action: Action,

    /// The key to use. Can be any string
    #[arg(short = 'k', long, required = true)]
    pub key: String,

    /// The size of the key to use. Either 256, 384, or 512
    #[arg(short = 's', long, value_enum, default_value = "256")]
    pub key_size: KeySize,

    /// The input file to use
    #[arg(short, long)]
    pub input_file: PathBuf,

    /// The output file to use
    #[arg(short, long, default_value = "output.txt")]
    pub output_file: PathBuf,
}

/// The different key sizes available
#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum KeySize {
    /// 256 bits
    #[value(name = "256")]
    Bits256 = 256,

    /// 384 bits
    #[value(name = "384")]
    Bits384 = 384,

    /// 512 bits
    #[value(name = "512")]
    Bits512 = 512,
}

impl KeySize {
    /// Get the block size of the algorithm in bytes
    pub fn block_size(&self) -> usize {
        match self {
            KeySize::Bits256 => 32,
            KeySize::Bits384 => 48,
            KeySize::Bits512 => 64,
        }
    }

    /// Get the number of rounds to use
    pub fn rounds(&self) -> usize {
        match self {
            KeySize::Bits256 => 14,
            KeySize::Bits384 => 16,
            KeySize::Bits512 => 18,
        }
    }
}

/// The action to take.
#[derive(Parser, Debug)]
pub enum Action {
    /// Encrypt a string
    Encrypt,

    /// Decrypt a string
    Decrypt,
}
