// src/file_handler.rs
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, Result};
use crate::engine::ChainedEngine;
use std::fs::OpenOptions;

pub struct FileHandler;

impl FileHandler {
    /// P2-04: Reads an input file in 4KB chunks, processes it through the engine, 
    /// and writes the output to a new file using buffered I/O.
    pub fn process_file(
        input_path: &str,
        output_path: &str,
        engine: &mut ChainedEngine,
        is_encrypting: bool,
    ) -> Result<()> {
        // 1. Open the input file and wrap it in a BufReader
        let input_file = File::open(input_path)?;
        let mut reader = BufReader::new(input_file);

        // 2. Create the output file and wrap it in a BufWriter
        let output_file = OpenOptions::new().append(true).open(output_path)?;
        let mut writer = BufWriter::new(output_file);

        // 3. Define our 4KB chunk buffer (4096 bytes)
        let mut buffer = [0u8; 4096];

        // 4. Loop through the file until EOF
        loop {
            let bytes_read = reader.read(&mut buffer)?;
            
            // If read returns 0, we've reached the end of the file
            if bytes_read == 0 {
                break;
            }

            // 5. Process only the valid bytes read in this chunk
            for byte in buffer[..bytes_read].iter_mut() {
                if is_encrypting {
                    *byte = engine.encrypt_byte(*byte);
                } else {
                    *byte = engine.decrypt_byte(*byte);
                }
            }

            // 6. Write the processed chunk to the BufWriter
            writer.write_all(&buffer[..bytes_read])?;
        }

        // 7. Ensure any remaining bytes in the writer's memory are pushed to the disk
        writer.flush()?;
        
        Ok(())
    }
}