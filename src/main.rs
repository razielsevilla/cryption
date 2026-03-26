use clap::{Parser, Subcommand};
use cryption::manager::CryptionManager;

#[derive(Parser)]
#[command(name = "Cryption CLI")]
#[command(about = "A high-performance encryption tool built in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// P3-01: File Mode for processing binary files (PDFs, images, etc.)
    File {
        /// -e: Encrypt the specified file
        #[arg(short, long)]
        encrypt: bool,

        /// -d: Decrypt the specified file
        #[arg(short, long)]
        decrypt: bool,

        /// -f: Path to the input file
        #[arg(short, long)]
        file: String,

        /// -p: The passkey for encryption/decryption
        #[arg(short, long)]
        passkey: String,

        /// The output path for the processed file
        #[arg(short, long)]
        output: String,
    },
    /// P3-01: Text Mode for quick string-based encryption
    Text {
        #[arg(short, long)]
        encrypt: bool,

        #[arg(short, long)]
        decrypt: bool,

        #[arg(short, long)]
        text: String,

        #[arg(short, long)]
        passkey: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::File { encrypt, decrypt, file, passkey, output } => {
            if encrypt {
                println!("🔒 Encrypting file: {}...", file);
                match CryptionManager::encrypt_file(&file, &output, &passkey) {
                    Ok(_) => println!("✅ Encryption complete! Saved to: {}", output),
                    Err(e) => eprintln!("❌ Error: {}", e),
                }
            } else if decrypt {
                println!("🔓 Decrypting file: {}...", file);
                match CryptionManager::decrypt_file(&file, &output, &passkey) {
                    Ok(_) => println!("✅ Decryption complete! Saved to: {}", output),
                    Err(e) => eprintln!("❌ Error: {}", e),
                }
            }
        }
        Commands::Text { encrypt, decrypt, text, passkey } => { 
            if encrypt {
                match CryptionManager::encrypt_text(&text, &passkey) {
                    Ok(ciphertext) => {
                        println!("🔒 Encrypted Text:");
                        println!("{}", ciphertext);
                    },
                    Err(e) => eprintln!("❌ Error: {}", e),
                }
            } else if decrypt {
                match CryptionManager::decrypt_text(&text, &passkey) {
                    Ok(plaintext) => {
                        println!("🔓 Decrypted Text:");
                        println!("{}", plaintext);
                    },
                    Err(e) => eprintln!("❌ Error: {}", e),
                }
            } else {
                eprintln!("❌ Error: Please specify either --encrypt (-e) or --decrypt (-d)");
            }
        }
    }
}