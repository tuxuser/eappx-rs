use std::{io::BufReader, path::PathBuf};
use uuid::Uuid;
use anyhow::Result;
use clap::{Parser, Subcommand};
use eappx::{
    EAppxFile,
    keys::{KeyCollection, KeyId}
};

/* Common arguments */

#[derive(Parser, Clone, Debug)]
struct KeyOptions {
    /// Use global testkey
    #[arg(long = "kt")]
    key_test: bool,
    /// Use keyfile
    #[arg(long = "kf")]
    key_file: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
struct InputFileOptions {
    /// Input package filepath
    #[arg(short, long)]
    package_file: PathBuf,
}

#[derive(Parser, Clone, Debug)]
struct OutputFileOptions {
    /// Output package filepath
    #[arg(short, long)]
    output_file: PathBuf,
}

#[derive(Parser, Clone, Debug)]
struct InputDirectoryOptions {
    /// Input directory path
    #[arg(short, long)]
    directory: PathBuf,
}

#[derive(Parser, Clone, Debug)]
struct OutputDirectoryOptions {
    /// Output directory path
    #[arg(short, long)]
    output_directory: PathBuf,
}

/* Subcommand options */

#[derive(Parser, Clone, Debug)]
struct PackOptions {
    #[clap(flatten)]
    key_options: KeyOptions,

    #[clap(flatten)]
    input_directory: InputDirectoryOptions,

    #[clap(flatten)]
    output_file: OutputFileOptions,
}

#[derive(Parser, Clone, Debug)]
struct UnpackOptions {
    #[clap(flatten)]
    key_options: KeyOptions,
    #[clap(flatten)]
    input_file: InputFileOptions,
    #[clap(flatten)]
    output_directory: OutputDirectoryOptions,
}

#[derive(Parser, Clone, Debug)]
struct EncryptOptions {
    #[clap(flatten)]
    key_options: KeyOptions,
    #[clap(flatten)]
    input_file: InputFileOptions,
    #[clap(flatten)]
    output_file: OutputFileOptions,
}

#[derive(Parser, Clone, Debug)]
struct DecryptOptions {
    #[clap(flatten)]
    key_options: KeyOptions,
    #[clap(flatten)]
    input_file: InputFileOptions,
    #[clap(flatten)]
    output_file: OutputFileOptions,
}

#[derive(Parser, Clone, Debug)]
struct InfoOptions {
    #[clap(flatten)]
    input_file: InputFileOptions,
}

/* Subcommands */

#[derive(Subcommand, Clone, Debug)]
enum Commands {
    /// Pack bare files into msix
    Pack(PackOptions),
    /// Unpack msix into bare files
    Unpack(UnpackOptions),
    /// Create bundle from bare files
    Bundle(PackOptions),
    /// Extract bare files from bundle
    Unbundle(UnpackOptions),
    /// Encrypt
    Encrypt(EncryptOptions),
    /// Decrypt
    Decrypt(DecryptOptions),
    /// Print infos about a package
    Info(InfoOptions)
}

/* Main opts */

#[derive(Parser, Debug)]
#[command(version = "1.0", author = "tuxuser", arg_required_else_help = true)]
struct Opts {
    /// Command
    #[command(subcommand)]
    cmd: Commands,

    #[arg(long, short)]
    verbose: bool,
}

fn main() -> Result<()>
{
    simple_logger::init_with_level(log::Level::Debug)?;
    let opts: Opts = Opts::parse();

    let mut key_collection = KeyCollection::default();

    match opts.cmd {
        Commands::Pack(_args)
        | Commands::Bundle(_args) => {
            todo!("Repacking")
        },
        Commands::Unpack(args)
        | Commands::Unbundle(args) => {
            let infile = args.input_file.package_file;
            let outdir = args.output_directory.output_directory;
            println!("Using file path: {:?}", infile);

            if let Some(key_file) = args.key_options.key_file {
                let mut keyfile = std::fs::File::open(key_file)?;
                let loaded_keys = KeyCollection::from_reader(&mut keyfile)?;

                key_collection.extend(loaded_keys.keys);
            }

            if args.key_options.key_test {
                // Add global testkey
                key_collection.add(
                    KeyId::Guid((
                        Uuid::parse_str("ddafcf67-7b2c-086d-302b-8adac1bdd3a7")?,
                        Uuid::parse_str("7d53aeb8-5922-f062-b1d7-7e09f5a187a0")?
                    )),
                    hex::decode("9fe75f879e95a5d7f3715c30fce71067fc346efd680fa25e3c737d76acb72b9d")?
                );
            }

            let file = std::fs::File::open(infile)?;
            let mut bufreader = BufReader::new(file);
            let mut eappx = EAppxFile::from_stream(&mut bufreader)?;
        
            println!("Got all keys: {}", key_collection.has_required_keys(&eappx.header.key_ids));
            println!("{eappx}");
            eappx.load_keys(&key_collection)?;
        
            if !outdir.exists() {
                println!("Create directory: {:?}", &outdir);
                std::fs::create_dir_all(&outdir)?;
            }
            
            eappx.extract(
                &mut bufreader,
                &outdir
            )?;
        },
        Commands::Encrypt(_args) => {
            todo!("Converting zip-style msix/appx to emsix/eappx")
        },
        Commands::Decrypt(_args) => {
            todo!("Converting emsix/eappx to zip-style msix/appx")
        },
        Commands::Info(args) => {
            let file = std::fs::File::open(args.input_file.package_file)?;
            let mut bufreader = BufReader::new(file);
            let eappx = EAppxFile::from_stream(&mut bufreader)?;
            println!("{eappx}");
            println!("Verifying");
            eappx.verify_blockmap_files(&mut bufreader)?;
        },
    }

    Ok(())
}