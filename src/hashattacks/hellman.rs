use std::{
    path::{Path, PathBuf},
    sync::{atomic::{AtomicBool, Ordering}, Arc}
};

use log::info;
use rand::prelude::*;

use crate::messagehash::{HashValue, MessageHash};
use table::*;
use tableio::*;

use super::{set_ctrlc_handler, AttackResult, AttackState, HashAttack};


mod table;
mod tableio;


fn truncate_hash(hash_value: &HashValue, hash_size_in_bytes: usize) -> Vec<u8> {
    let prefix_size = HashValue::len() - hash_size_in_bytes;

    hash_value[prefix_size..].to_vec()
}   
    
fn generate_random_byte_vector(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    
    (0..size)
        .map(|_| rng.gen())
        .collect()
}

fn reduction_function(hash: &Vec<u8>, prefix: &Vec<u8>) -> Vec<u8> {
    let mut reducted_value = Vec::with_capacity(hash.len() + prefix.len());
    
    reducted_value.extend_from_slice(prefix);
    reducted_value.extend_from_slice(hash);

    reducted_value
}

fn bytes_to_string(bytes: &Vec<u8>) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}


pub struct Hellman {
    state: AttackState,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    tables_number: TableNumber,
    chain_number: u64,
    chain_length: u64,
    table_directory: TableDirectory,
    table_file_format: String
}

impl Hellman {
    pub fn build(
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        reduction_output_size_in_bytes: usize,
        tables_number: TableNumber,
        chain_number: u64,
        chain_length: u64,
        table_directory_path: &Path,
        table_file_format: &str
    ) -> Result<Self, &'static str> {
        if hash_size_in_bytes > HashValue::len() {
            return Err("Invalid hash size");
        }
        if reduction_output_size_in_bytes <= hash_size_in_bytes {
            return Err("Invalid reduction output size");
        }
        if tables_number.on_disk() == 0 {
            return Err("Invalid number of tables");
        }
        match table_file_format {
            "json" | "bin" => (),
            _ => return Err("Invalid table file format")
        };

        let reduction_prefix_size_in_bytes =
            reduction_output_size_in_bytes - hash_size_in_bytes;
        let table_directory = TableDirectory::new(
            &table_directory_path,
            hash_size_in_bytes,
            reduction_prefix_size_in_bytes,
            &table_file_format
        );
        let table_file_format = table_file_format.to_string(); 

        Ok(
            Self {
                state: initial_state,
                hash_size_in_bytes,
                reduction_prefix_size_in_bytes,
                tables_number,
                chain_number,
                chain_length,
                table_directory,
                table_file_format
            }
        )
    }
    
    fn calculate_last_point(
        &mut self,
        chain_length: u64,
        first_point: &Vec<u8>,
        prefix: &Vec<u8>
    ) -> Vec<u8> {
        let mut last_point = first_point.clone();

        for _ in 1..=chain_length {
            let reducted_value = reduction_function(&last_point, prefix);
            let hash = &self.state.hash_message(&reducted_value);

            last_point = truncate_hash(&hash, self.hash_size_in_bytes);
        }

        last_point
    }

    fn create_preprocessing_table(
        &mut self, 
        running: &Arc<AtomicBool>
    ) -> Table {
        let prefix = generate_random_byte_vector(
            self.reduction_prefix_size_in_bytes
        );
        let mut table = Table::new(Vec::new(), prefix);

        for i in 1..=self.chain_number {
            if !running.load(Ordering::SeqCst) {
                info!(
                    "TERM, Hellman.create_preprocessing_table, Iteration: {}",
                    i
                );
                break;
            }
            
            let first_point = generate_random_byte_vector(
                self.hash_size_in_bytes
            );
            let last_point = self.calculate_last_point(
                self.chain_length,
                &first_point, 
                table.prefix()
            );

            let entry = Chain::new(first_point, last_point);

            table.push(entry);
        }

        table
    }
    
    // Helper function.
    fn table_filepath(&self, table_index: usize) -> PathBuf {
        self.table_directory.table_filepath(
            self.chain_number,
            self.chain_length,
            table_index
        ) 
    }
    
    // Helper function (alias).
    fn get_free_index(&self, start_index: usize) -> usize {
        self.table_directory.get_free_index(
            self.chain_number,
            self.chain_length,
            start_index
        )
    }

    // Helper function (alias).
    fn read_table_filepaths(&self) -> Vec<PathBuf> {
        self.table_directory.read_table_filepaths(
            self.chain_number,
            self.chain_length,
            self.tables_number.on_disk()
        ).expect("Failed to read table directory contents")
    }

    pub fn generate(&mut self) -> Result<(), &'static str> {
        let running = set_ctrlc_handler();
       
        info!("INIT, Tables: {}", self.tables_number.on_disk());
   
        self.table_directory.create_directory();

        let mut j = 1;

        for i in 1..=self.tables_number.on_disk() {
            if !running.load(Ordering::SeqCst) {
                info!("TERM, Hellman.generate, Iteration: {}", i);
                return Ok(());
            }
            
            let mut table = self.create_preprocessing_table(&running);
          
            // Sort the table by last points for future binary search.
            table.sort();

            j = self.get_free_index(j);
            let filepath = self.table_filepath(j);

            table.to_file(&filepath, &self.table_file_format)?;
           
            info!("SUCCESS, Filepath: {}", filepath.display());
        }

        Ok(())
    }

    pub fn convert(
        &self,
        output_format: &str,
        table_index: usize,
        force: bool
    ) -> Result<(), &'static str> {
        let mut filepath = self.table_filepath(table_index);

        let table_in = match Table::from_file(
            &filepath, 
            &self.table_file_format, 
            usize::max_value()
        ) {
            Ok(table) => table,
            Err(e) => {
                info!(
                    "FAILURE, Table: {}, Iteration: {}", 
                    filepath.display(),
                    1
                );
                return Err(e);
            }
        };

        let mut output_table_directory = self.table_directory.clone();
        output_table_directory.table_file_format = output_format.to_string();
        
        // Choose whether to keep table index in converted table.
        // Table with the same index will be overwritten.
        filepath = if force {
            output_table_directory.table_filepath(
                self.chain_number,
                self.chain_length,
                table_index
            )
        }
        else {
            output_table_directory.get_free_filepath(
                self.chain_number,
                self.chain_length,
                1
            )
        };

        match table_in.to_file(&filepath, output_format) {
            Ok(_) => (),
            Err(e) => {
                info!(
                    "FAILURE, Table: {}, Iteration: {}", 
                    filepath.display(),
                    2
                );
                return Err(e);
            }
        };

        info!("SUCCESS, Filepath: {}", filepath.display());

        Ok(())
    }

    fn init_current_points(&mut self) -> Vec<Vec<u8>> {
        let messagehash = self.state.messagehash();
        let hash = truncate_hash(
            messagehash.hash_value(),
            self.hash_size_in_bytes
        ); 
        
        vec![hash.clone(); self.tables_number.on_disk()]
    }

    fn process_tables(
        &mut self,
        hash: &Vec<u8>,
        points: &mut [Vec<u8>],
        tables: &Vec<Table>,
        filepaths: &[PathBuf],
        running: &Arc<AtomicBool>
    ) -> (Result<AttackResult, &'static str>, u64) {
        let mut iteration: u64 = 1;

        if points.len() != tables.len() || tables.len() != filepaths.len() {
            return (Err("Invalid container sizes"), iteration);    
        }

        while iteration <= self.chain_length {
            if !running.load(Ordering::SeqCst) {
                info!("TERM, Hellman.process_tables, Iteration: {}", iteration);
                return (Err("Attack terminated"), iteration);
            }

            // TODO add multithreading
            for (j, table) in tables.iter().enumerate() {
                if let Some(preimage) = self.try_find_point(
                    &hash,
                    &table,
                    &mut points[j],
                    iteration
                ) {
                    info!(
                        "SUCCESS, Table: {}, Iteration: {}, \
                        Preimage: \"{}\", Preimage hash: {}",
                        filepaths[j].display(),
                        iteration,
                        preimage.message(),
                        preimage.hash_value()
                    );
                    
                    let result = AttackResult::Preimage(preimage);
                   
                    let iteration = iteration * tables.len() as u64 + j as u64;

                    return (Ok(result), iteration);
                }
            }     
            
            iteration += 1;
        }

        (Err("Failed to find preimage"), iteration)
    }

    fn try_find_point(
        &mut self,
        hash: &Vec<u8>,
        table: &Table,
        point: &mut Vec<u8>,
        iteration: u64
    ) -> Option<MessageHash> {
        if let Some(Chain(first_point, _)) = table
            .search_by_last_point(point)
        {
            let result = self.try_find_preimage(
                hash,
                table,
                first_point,
                iteration
            );

            return result;
        }
        else {
            *point = self.calculate_last_point(
                1, 
                &point.clone(), 
                table.prefix()
            );
        } 

        None
    }

    fn try_find_preimage(
        &mut self,
        hash: &Vec<u8>,
        table: &Table,
        first_point: &Vec<u8>,
        iteration: u64
    ) -> Option<MessageHash> {
        let prefixless = self.calculate_last_point(
            self.chain_length - iteration,
            first_point,
            table.prefix()
        );

        let preimage_bytes = reduction_function(
            &prefixless, 
            table.prefix()
        );
        
        let preimage_hash = &self.state.hash_message(
            &preimage_bytes
        );

        if *hash != truncate_hash(&preimage_hash, self.hash_size_in_bytes) {
            return None;
        }

        let preimage = bytes_to_string(&preimage_bytes);
        let messagehash = MessageHash::new(
            &preimage,
            preimage_hash.clone()
        );

        return Some(messagehash);
    }
}

impl HashAttack for Hellman {
    fn initial_state(&self) -> &AttackState {
        &self.state
    }
    fn initial_state_mut(&mut self) -> &mut AttackState {
        &mut self.state
    }
    
    fn attack(
        &mut self,
        running: Arc<AtomicBool>
    ) -> Result<AttackResult, &'static str> {
        info!(
            "INIT, Message: \"{}\", Hash: {}",
            self.state.messagehash().message(), 
            self.state.messagehash().hash_value()
        );
      
        let filepaths = self.read_table_filepaths();
        
        let mut points = self.init_current_points();
        let hash = points[0].clone();

        let mut total_iterations: u64 = 0;
        let memory_tables_number = self.tables_number.in_memory();

        for i in (0..filepaths.len()).step_by(memory_tables_number) {
            let current_filepaths = &filepaths[i..(i + memory_tables_number)];

            let tables = Table::from_files(
                current_filepaths,
                &self.table_file_format,
                self.chain_number as usize
            ); 

            let (result, iteration) = self.process_tables(
                &hash,
                &mut points[i..(i + memory_tables_number)],
                &tables,
                current_filepaths,
                &running
            ); 

            if let Ok(AttackResult::Preimage(preimage)) = result {
                info!(
                    "SUCCESS, Iteration: {}, \
                    Preimage: \"{}\", Preimage hash: {}",
                    total_iterations + iteration,
                    preimage.message(),
                    preimage.hash_value()
                );

                return Ok(AttackResult::Preimage(preimage));
            }

            for filepath in current_filepaths {
                info!(
                    "FAILURE, Table: {}, Iteration: {}",
                    filepath.display(),
                    iteration - 1
                );
            }

            total_iterations += (iteration - 1) * tables.len() as u64;
        }
     
        info!("FAILURE, Iteration: {}", total_iterations);

        Err("Attack failed")
    }
}
