use anyhow::bail;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use pem::Pem;
use plugin_defs::{Package, PackageMetadata};
use rand::thread_rng;
use std::path::{Path, PathBuf};
use std::{env, fs};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenKeypair {
        #[clap(value_parser)]
        output: Option<String>,
    },
    Pack {
        #[clap(value_parser)]
        library: String,
        #[clap(short, long, value_parser)]
        metadata: Option<String>,
        #[clap(short, long, value_parser)]
        key: Option<String>,
        #[clap(short, long, value_parser)]
        output: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli: Cli = Cli::parse();

    match cli.command {
        Commands::GenKeypair { output } => gen_keypair(output),
        Commands::Pack {
            library,
            metadata,
            key,
            output,
        } => pack(library, metadata, key, output),
    }
}

fn gen_keypair(output_path: Option<String>) -> anyhow::Result<()> {
    let output_path = if let Some(path) = output_path {
        PathBuf::from(path)
    } else {
        env::current_dir()?
    };
    fs::create_dir_all(&output_path)?;
    let keypair = SigningKey::generate(&mut thread_rng());
    let pubkey = Pem {
        tag: "ed25519 dalek public key".to_uppercase(),
        contents: keypair.verifying_key().as_bytes().to_vec(),
    };
    let key = Pem {
        tag: "ed25519 dalek key".to_uppercase(),
        contents: keypair.to_bytes().to_vec(),
    };
    fs::write(output_path.join("public-key.pem"), pem::encode(&pubkey))?;
    fs::write(output_path.join("key.pem"), pem::encode(&key))?;
    Ok(())
}

fn pack(
    library: String,
    metadata: Option<String>,
    key: Option<String>,
    output: Option<String>,
) -> anyhow::Result<()> {
    check_file_exist(&library)?;
    let library = PathBuf::from(library);
    let metadata = if let Some(path) = metadata {
        PathBuf::from(path)
    } else {
        library
            .parent()
            .unwrap()
            .join("../../modules/spider/metadata.json")
    };
    check_file_exist(&metadata)?;

    let key = if let Some(path) = key {
        PathBuf::from(path)
    } else {
        env::current_dir()?.join("key.pem")
    };
    check_file_exist(&key)?;

    let keypair = fs::read(key)?;
    let keypair = pem::parse(keypair)?.contents;
    let keypair = SigningKey::from_bytes(&keypair.try_into().unwrap());

    let buf = fs::read(metadata)?;
    let metadata: PackageMetadata = serde_json::from_slice(buf.as_slice())?;

    let out_name = format!("{}.cdp", metadata.name);
    let output = if let Some(path) = output {
        PathBuf::from(path).join(out_name)
    } else {
        library.parent().unwrap().join(out_name)
    };

    let library = fs::read(library)?;
    let package = Package::new(metadata, library);

    let exported = package.export(keypair)?;

    fs::create_dir_all(output.parent().unwrap())?;
    fs::write(output, exported.as_slice())?;

    Ok(())
}

fn check_file_exist<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    if !path.as_ref().is_file() {
        bail!("cannot find file: {:?}", path.as_ref());
    }
    Ok(())
}
