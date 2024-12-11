use std::{
    fs,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
};

use rand::prelude::*;
use serde::{Serialize, Deserialize};

use crate::messagehash::HashValue;

use super::{AttackResult, AttackState, HashAttack};


const TABLES_DIRECTORY_PATH: &str = "tables";


// TODO change to a macros
fn table_filepath(index: usize) -> String {
    format!("{TABLES_DIRECTORY_PATH}/table_{index}")
}

fn bytes_to_string(bytes: &Vec<u8>) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}


#[derive(Debug, Deserialize, Serialize, Clone)]
struct TableEntry {
    first_value: Vec<u8>,
    last_value: Vec<u8>
}

impl TableEntry { 
    fn new(first_value: Vec<u8>, last_value: Vec<u8>) -> Self {
        Self { first_value, last_value }
    }
}


#[derive(Debug, Deserialize, Serialize)]
struct Table {
    entries: Vec<TableEntry>,
    prefix: Vec<u8>
}

impl Table {
    fn new(entries: Vec<TableEntry>, prefix: Vec<u8>) -> Self {
        Self { entries, prefix }
    }

    fn read_table(filepath: &str) -> std::io::Result<Self> {
        let json: String = fs::read_to_string(filepath)?;
        
        let table: Table = serde_json::from_str(&json).unwrap();

        Ok(table)
    }

    fn push(&mut self, entry: TableEntry) {
        self.entries.push(entry);
    }

    fn iter(&self) -> std::slice::Iter<TableEntry> {
        self.entries.iter()
    }

    fn store_table(&self, filepath: &str) -> std::io::Result<()> {
        let json = serde_json::to_string(self).unwrap();

        fs::write(filepath, json)?;

        Ok(())
    }
}


pub struct Hellman {
    state: AttackState,
    hash_size_in_bytes: usize,
    redundancy_prefix_size_in_bytes: usize,
    tables_number: usize,
    stored_tables_number: usize,
    variable_number: u32,
    iteration_count: u32,
    values: Vec<Vec<u8>>
}

impl Hellman {
    pub fn build(
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        redundancy_output_size_in_bytes: usize,
        tables_number: usize,
        stored_tables_number: usize,
        variable_number: u32,
        iteration_count: u32
    ) -> Result<Self, &'static str> {
        if hash_size_in_bytes > HashValue::len() {
            return Err("Invalid hash size");
        }
        if redundancy_output_size_in_bytes <= hash_size_in_bytes {
            return Err("Invalid redundancy output size");
        }
        if tables_number == 0 {
            return Err("Invalid number of tables");
        }
        if stored_tables_number > tables_number {
            return Err("Invalid number of stored tables");
        }

        let redundancy_prefix_size_in_bytes =
            redundancy_output_size_in_bytes - hash_size_in_bytes; 
        let values: Vec<Vec<u8>> = Vec::new();

        let mut hellman = Self {
            state: initial_state,
            hash_size_in_bytes,
            redundancy_prefix_size_in_bytes,
            tables_number,
            stored_tables_number,
            variable_number,
            iteration_count,
            values
        };
        
        let messagehash = hellman.state.messagehash();
        let hash = hellman.truncate_hash(messagehash.hash_value()); 
        hellman.values = vec![hash.clone(); hellman.tables_number];

        Ok(hellman)
    }
    
    fn truncate_hash(&self, hash_value: &HashValue) -> Vec<u8> {
        let prefix_size = HashValue::len() - self.hash_size_in_bytes;

        hash_value[prefix_size..].to_vec()
    }   
    
    fn generate_random_byte_vector(&self, size: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        
        (0..size)
            .map(|_| rng.gen())
            .collect()
    }

    fn redundancy_function(
        &self,
        hash: &Vec<u8>,
        prefix: &Vec<u8>
    ) -> Vec<u8> {
        let mut redundant_value = Vec::with_capacity(hash.len() + prefix.len());
        
        redundant_value.extend_from_slice(prefix);
        redundant_value.extend_from_slice(hash);

        redundant_value
    }
    
    fn calculate_last_value(
        &mut self,
        iteration_count: u32,
        first_value: &Vec<u8>,
        prefix: &Vec<u8>
    ) -> Vec<u8> {
        let mut last_value = first_value.clone();

        for _ in 1..=iteration_count {
            let redundant_value = self.redundancy_function(&last_value, prefix);
            let hash = &self.state.hash_message(&redundant_value);

            last_value = self.truncate_hash(&hash);
        }

        last_value
    }

    fn create_preprocessing_table(
        &mut self, 
        running: &Arc<AtomicBool>
    ) -> Table {
        let prefix = self.generate_random_byte_vector(
            self.redundancy_prefix_size_in_bytes
        );
        let mut table = Table::new(Vec::new(), prefix);

        for i in 1..=self.variable_number {
            if !running.load(Ordering::SeqCst) {
                println!(
                    "[INFO] Table generation terminated after {} iterations",
                    i
                );
                break;
            }
            
            let first_value = self.generate_random_byte_vector(
                self.hash_size_in_bytes
            );
            let last_value = self.calculate_last_value(
                self.iteration_count,
                &first_value, 
                &table.prefix
            );

            let entry = TableEntry::new(first_value, last_value);

            table.push(entry);
        }

        table
    }

    fn create_preprocessing_tables(
        &mut self,
        running: &Arc<AtomicBool>
    ) -> Vec<Table> {
        let mut tables = Vec::new();

        for i in 1..=self.stored_tables_number {
            if !running.load(Ordering::SeqCst) {
                println!("[INFO] Table {} generation terminated", i);
                break;
            }
            
            let table = self.create_preprocessing_table(&running);
           
            let filepath = table_filepath(i);

            table.store_table(&filepath)
                .expect("Failed to write table to disk");
        }

        for i in 1..=(self.tables_number - self.stored_tables_number) {
            if !running.load(Ordering::SeqCst) {
                println!("[INFO] Table {} generation terminated", i);
                break;
            }
            
            let table = self.create_preprocessing_table(&running);

            tables.push(table);
        }

        tables
    }

    fn try_find_value(
        &mut self,
        table: &Table,
        value_index: usize,
        iteration: u32
    ) -> Option<String> {
        if let Some(TableEntry { first_value, last_value: _ }) = table
            .iter()
            .find(|TableEntry { first_value: _, last_value }|
                *last_value == self.values[value_index])
        {
            let hash = self.values[0].clone();
        
            let prefixless = self.calculate_last_value(
                self.iteration_count - iteration,
                first_value,
                &table.prefix
            );

            let preimage_bytes = self.redundancy_function(
                &prefixless, 
                &table.prefix
            );
            
            let preimage_hash = &self.state.hash_message(
                &preimage_bytes
            );

            if *hash != self.truncate_hash(&preimage_hash) {
                return None;
            }

            let preimage = bytes_to_string(&preimage_bytes);

            println!(
                "[SUCCESS] Found preimage on iteration {}!\n{}\n{:x}\t{}\n",
                iteration,
                self.state.messagehash(),
                preimage_hash,
                preimage
            );

            return Some(preimage);
        }
        else {
            self.values[value_index] = self.calculate_last_value(
                1, 
                &self.values[value_index].clone(), 
                &table.prefix
            );
        } 

        None
    }
}

impl HashAttack for Hellman {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        println!(
            "[INFO] Initialising Hellman's attack...\n{}\n",
            self.state.messagehash()
        );
        println!("[INFO] Generating preprocessing tables...");
       
        if self.stored_tables_number != 0 {
            // Remove previous tables.
            let _ = fs::remove_dir_all(TABLES_DIRECTORY_PATH);
            fs::create_dir(TABLES_DIRECTORY_PATH)
                .expect("Failed to create table directory");
        }

        let tables = self.create_preprocessing_tables(&running);

        println!("[INFO] Searching for a preimage...");

        let mut iteration = 1;

        while iteration <= self.iteration_count {
            if !running.load(Ordering::SeqCst) {
                println!(
                    "[INFO] Attack terminated after {} iterations",
                    iteration
                );
                break;
            }
            
            // TODO read and process multiple tables at once
            for table_index in 1..=self.stored_tables_number {
                let filepath = table_filepath(table_index);

                let table = Table::read_table(&filepath)
                    .expect("Failed to deserialize table");

                if let Some(preimage) = self.try_find_value(
                    &table,
                    table_index - 1,
                    iteration
                ) {
                    return AttackResult::Preimage(preimage);
                }
            } 

            for (index, table) in tables.iter().enumerate() {
                let value_index = index + self.stored_tables_number;
                
                if let Some(preimage) = self.try_find_value(
                    table,
                    value_index,
                    iteration
                ) {
                    return AttackResult::Preimage(preimage);
                }
            }

            iteration += 1;
        }

        println!(
            "[FAILURE] Preimage was not found in {} iterations\n",
            iteration - 1
        );
       
        if self.stored_tables_number != 0 {
            fs::remove_dir_all(TABLES_DIRECTORY_PATH)
                .expect("Failed to delete stored tables");
        }

        AttackResult::Failure
    }
}
