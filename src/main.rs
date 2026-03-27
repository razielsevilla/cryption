mod gui;

use clap::{Parser, Subcommand};
use cryption::manager::CryptionManager;

#[derive(Parser)]
#[command(name = "Cryption CLI")]
#[command(about = "A high-performance encryption tool built in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            println!("🚀 No command provided. Launching Cryption Desktop Environment...");
            // Safely map the specific iced::Error into our generic Boxed error
            gui::run_app().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        }   
        Some(Commands::File { encrypt, decrypt, file, passkey, output }) => {
            use indicatif::{ProgressBar, ProgressStyle};
            
            let file_metadata = std::fs::metadata(&file)?;
            let file_size = file_metadata.len();
            
            // P3-03: Initialize the progress bar
            let pb = ProgressBar::new(file_size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"));

            if encrypt {
                println!("🔒 Encrypting file: {}...", file);
                // When encrypting, we process the whole file (header is added separately but not tracked in the callback)
                // Actually, manager.rs passes the callback to FileHandler which processes the source file.
                match CryptionManager::encrypt_file(&file, &output, &passkey, Some(|bytes| pb.set_position(bytes))) {
                    Ok(_) => {
                        pb.finish_with_message("Done");
                        println!("✅ Encryption complete! Saved to: {}", output);
                    },
                    Err(e) => {
                        pb.abandon();
                        eprintln!("❌ Error: {}", e);
                    }
                }
            } else if decrypt {
                println!("🔓 Decrypting file: {}...", file);
                // When decrypting, the payload is slightly smaller than the file size
                let payload_size = file_size.saturating_sub(34 + 32); // Header(34) + MAC(32)
                pb.set_length(payload_size);

                match CryptionManager::decrypt_file(&file, &output, &passkey, Some(|bytes| pb.set_position(bytes))) {
                    Ok(_) => {
                        pb.finish_with_message("Done");
                        println!("✅ Decryption complete! Saved to: {}", output);
                    },
                    Err(e) => {
                        pb.abandon();
                        eprintln!("❌ Error: {}", e);
                    }
                }
            }   
        }
        Some(Commands::Text { encrypt, decrypt, text, passkey }) => { 
            if encrypt {
                match CryptionManager::encrypt_text(&text, &passkey) {
                    Ok(ciphertext) => {
                        println!("🔒 Encrypted Text:");
                        println!("{}", ciphertext);
                    },
                    Err(e) => eprintln!("❌ Error: {}", e), // Automatically prints CryptionError format
                }
            } else if decrypt {
                match CryptionManager::decrypt_text(&text, &passkey) {
                    Ok(plaintext) => {
                        println!("🔓 Decrypted Text:");
                        println!("{}", plaintext);
                    },
                    Err(e) => eprintln!("❌ Error: {}", e), // Automatically prints CryptionError format
                }
            } else {
                eprintln!("❌ Error: Please specify either --encrypt (-e) or --decrypt (-d)");
            }
        }
    }
    Ok(())
}