// src/file_handler.rs
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, Result, Seek, SeekFrom};
use crate::engine::ChainedEngine;
use std::fs::OpenOptions;

pub struct FileHandler;

impl FileHandler {
    /// P2-04: Reads an input file in chunks, processes it through the engine, 
    /// and writes the output to a new file using buffered I/O.
    pub fn process_file<F>(
        input_path: &str,
        output_path: &str,
        engine: &mut ChainedEngine,
        is_encrypting: bool,
        offset: u64,
        limit: Option<u64>,
        mut progress_callback: Option<F>, // NEW: Accepts an optional callback
    ) -> Result<()> 
    where 
        F: FnMut(u64), // The callback takes a u64 (bytes processed)
    {
        // 1. Open the input file, seek to offset, and wrap it in a BufReader
        let mut input_file = File::open(input_path)?;
        input_file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(input_file);

        // 2. Create the output file and wrap it in a BufWriter
        let output_file = OpenOptions::new()
            .append(true)
            .create(true) 
            .open(output_path)?;
        let mut writer = BufWriter::new(output_file);

        // 3. Define our 4KB chunk buffer (4096 bytes)
        let mut buffer = [0u8; 4096];
        let mut bytes_processed = 0u64;

        // 4. Loop through the file
        loop {
            let to_read = match limit {
                Some(l) => std::cmp::min(buffer.len() as u64, l - bytes_processed) as usize,
                None => buffer.len(),
            };
            
            if to_read == 0 {
                break;
            }

            let bytes_read = reader.read(&mut buffer[..to_read])?;
            
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
            bytes_processed += bytes_read as u64;

            // NEW: Fire the callback with the current progress
            if let Some(ref mut callback) = progress_callback {
                callback(bytes_processed);
            }
        }

        writer.flush()?;
        Ok(())
    }
}