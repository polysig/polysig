//! Command line tool to generate keys.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use polysig_driver::PartyKeys;
use polysig_protocol::{hex, KeyType, Keypair};
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

/// Meeting room websocket server.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct KeygenService {
    #[clap(subcommand)]
    cmd: Command,
}

/// Program commands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate PEM-encoded keypair and write to file.
    Keypair {
        /// Force overwrite if the file exists.
        #[clap(short, long)]
        force: bool,

        /// Write hex-encoded public key to a file.
        #[clap(long)]
        public_key: Option<PathBuf>,

        /// Write keypair to this file.
        file: PathBuf,
    },
    /// Generate key material for a number of parties.
    TestKeys {
        /// Force overwrite if the file exists.
        #[clap(short, long)]
        force: bool,

        /// Number of keys to generate.
        #[clap(short, long)]
        num: u8,

        /// Encode the verifier as serde JSON.
        #[clap(short, long)]
        verifier_serde: bool,

        /// Type of key to generate.
        #[clap(short, long)]
        key_type: KeyType,

        /// Write keys to this file as JSON.
        file: Option<PathBuf>,
    },
}

/// Parse arguments and run the program.
fn run() -> Result<()> {
    let args = KeygenService::parse();
    match args.cmd {
        Command::Keypair {
            force,
            public_key,
            file,
        } => generate_keypair(file, force, public_key)?,
        Command::TestKeys {
            num,
            force,
            key_type,
            file,
            verifier_serde,
        } => generate_test_keys(
            file,
            force,
            num,
            key_type,
            verifier_serde,
        )?,
    }
    Ok(())
}

/// Generate test keys.
fn generate_test_keys(
    path: Option<PathBuf>,
    force: bool,
    num: u8,
    key_type: KeyType,
    verifier_serde: bool,
) -> Result<()> {
    if let Some(path) = &path {
        if path.exists() && !force {
            bail!(
                "file {} already exists, use --force to overwrite",
                path.display()
            );
        }
    }

    let mut keys = Vec::with_capacity(num as usize);
    for _ in 0..num {
        let encrypt = Keypair::generate()?;
        let (private, public) = match key_type {
            KeyType::Ecdsa => {
                let signer =
                    k256::ecdsa::SigningKey::random(&mut OsRng);
                let verifier = if verifier_serde {
                    serde_json::to_vec(signer.verifying_key())?
                } else {
                    signer.verifying_key().to_sec1_bytes().to_vec()
                };
                (signer.to_bytes().to_vec(), verifier)
            }
            KeyType::Ed25519 => {
                let signer =
                    ed25519_dalek::SigningKey::generate(&mut OsRng);
                let verifier = if verifier_serde {
                    serde_json::to_vec(&signer.verifying_key())?
                } else {
                    signer.verifying_key().to_bytes().to_vec()
                };
                (signer.to_bytes().to_vec(), verifier)
            }
            KeyType::Schnorr => {
                let signer =
                    k256::schnorr::SigningKey::random(&mut OsRng);
                let verifier = if verifier_serde {
                    serde_json::to_vec(signer.verifying_key())?
                } else {
                    signer.verifying_key().to_bytes().to_vec()
                };
                (signer.to_bytes().to_vec(), verifier)
            }
            KeyType::Noise => {
                bail!("noise key type is not supported for test keys")
            }
        };

        let party = PartyKeys {
            encrypt,
            sign: Keypair::new(private, public, key_type),
        };
        keys.push(party);
    }

    if let Some(path) = &path {
        let mut writer = fs::File::create(path)?;
        serde_json::to_writer_pretty(&mut writer, &keys)?;
    } else {
        serde_json::to_writer_pretty(std::io::stdout(), &keys)?;
    }

    Ok(())
}

/// Generate keypair and write to file.
fn generate_keypair(
    path: PathBuf,
    force: bool,
    public_key: Option<PathBuf>,
) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "file {} already exists, use --force to overwrite",
            path.display()
        );
    }

    let keypair = Keypair::generate()?;
    let pem = keypair.encode_pem();

    let mut file = fs::File::create(&path)?;
    file.write_all(pem.as_bytes())?;
    file.flush()?;

    println!("{}", hex::encode(keypair.public_key()));

    if let Some(public_key) = public_key {
        let public_key_hex = hex::encode(keypair.public_key());
        fs::write(public_key, public_key_hex.as_bytes())?;
    }

    Ok(())
}

#[doc(hidden)]
pub fn main() -> Result<()> {
    use tracing_subscriber::{
        layer::SubscriberExt, util::SubscriberInitExt,
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "polysig_meeting_server=info".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    Ok(())
}
