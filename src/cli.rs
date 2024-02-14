use clap::{Parser, ValueEnum};

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
}

/// The different key sizes available
#[derive(ValueEnum, Debug, Clone)]
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

/// The action to take.
#[derive(Parser, Debug)]
pub enum Action {
    /// Encrypt a string
    Encrypt {
        /// The string to encrypt
        #[arg(required = true)]
        input: String,
    },

    /// Decrypt a string
    Decrypt {},
}
