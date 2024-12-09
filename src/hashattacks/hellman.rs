use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use rand::prelude::*;

use crate::messagehash::{HashValue, MessageHash};

use super::{AttackResult, AttackState, HashAttack};


pub struct Hellman {
    state: AttackState,
    hash_size_in_bytes: usize,
    redundancy_prefix_size_in_bytes: usize,
    tables_num: u32,
    variable_number: u32,
    iteration_count: u32,
}

impl Hellman {
    pub fn build(
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        redundancy_output_size_in_bytes: usize,
        tables_num: u32,
        variable_number: u32,
        iteration_count: u32
    ) -> Result<Self, &'static str> {
        if hash_size_in_bytes > HashValue::len() {
            return Err("Invalid hash size");
        }
        if redundancy_output_size_in_bytes <= hash_size_in_bytes {
            return Err("Invalid redundancy output size");
        }

        let redundancy_prefix_size_in_bytes =
            redundancy_output_size_in_bytes - hash_size_in_bytes; 

        Ok(
            Self {
                state: initial_state,
                hash_size_in_bytes,
                redundancy_prefix_size_in_bytes,
                tables_num,
                variable_number,
                iteration_count
            }
        )
    }
    
    fn truncate_hash(&self, hash_value: &HashValue) -> Vec<u8> {
        let prefix_size = HashValue::len() - self.hash_size_in_bytes;

        hash_value[prefix_size..].to_vec()
    }   
    
    fn generate_redundancy_prefix(&self) -> Vec<u8> {
        let mut rng = thread_rng();
        
        (0..self.redundancy_prefix_size_in_bytes)
            .map(|_| rng.gen())
            .collect()
    }

    fn redundancy_function(
        &self,
        hash: &Vec<u8>,
        prefix: &Vec<u8>
    ) -> Result<Vec<u8>, &'static str> {
        let hash_len = hash.len();
        let prefix_len = prefix.len();

        if hash_len != self.hash_size_in_bytes {
            return Err("Invalid hash size");
        }
        if prefix_len != self.redundancy_prefix_size_in_bytes {
            return Err("Invalid redundancy prefix size");
        }

        let mut result = Vec::with_capacity(hash_len + prefix_len);
        
        result.extend_from_slice(prefix);
        result.extend_from_slice(hash);

        Ok(result)
    }
    
    fn calculate_last_value(
        &mut self,
        iteration_count: u32,
        first_value: &Vec<u8>,
        prefix: &Vec<u8>
    ) -> Result<Vec<u8>, &'static str> {
        if first_value.len() != self.hash_size_in_bytes {
            return Err("Invalid first value size");
        }
        if prefix.len() != self.redundancy_prefix_size_in_bytes {
            return Err("Invalid redundancy prefix size");
        }
        
        let mut last_value = first_value.clone();

        for _ in 1..=iteration_count {
            let redundant_value = self.redundancy_function(&last_value, prefix)
                .unwrap();
            let hash = &self.state.hash_message(&redundant_value);

            last_value = self.truncate_hash(&hash);
        }

        Ok(last_value)
    }

    fn create_preprocessing_table(
        &mut self, 
        running: &Arc<AtomicBool>
    ) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>) {
        let mut table = Vec::new();
        let mut rng = thread_rng(); 
        let prefix = self.generate_redundancy_prefix();

        for i in 1..=self.variable_number {
            if !running.load(Ordering::SeqCst) {
                println!(
                    "[INFO] Table generation terminated after {} iterations",
                    i
                );
                break;
            }
            
            let first_value: Vec<u8> = (0..self.hash_size_in_bytes)
                .map(|_| rng.gen())
                .collect();
            let last_value = self.calculate_last_value(
                self.iteration_count,
                &first_value, 
                &prefix
            ).expect("Failed to calculate the last value");

            table.push((first_value, last_value));
        }

        (table, prefix)
    }

    fn create_preprocessing_tables(
        &mut self,
        running: &Arc<AtomicBool>
    ) -> Vec<(Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>)> {
        let mut tables = Vec::new();
        
        for i in 1..=self.tables_num {
            if !running.load(Ordering::SeqCst) {
                println!("[INFO] Table {} generation terminated", i);
                break;
            }
            
            tables.push(self.create_preprocessing_table(&running));

            println!("Table {} created", i);
        }

        tables
    }

    fn try_find_value(
        &mut self,
        hash: &Vec<u8>,
        table: &Vec<(Vec<u8>, Vec<u8>)>,
        prefix: &Vec<u8>,
        value: &mut Vec<u8>,
        iteration: u32
    ) -> Option<String> {
        if let Some((found_first, _)) = table
            .iter()
            .find(|(_, last)| *last == *value)
        {
            let prefixless = self.calculate_last_value(
                self.iteration_count - iteration,
                found_first,
                prefix
            ).unwrap();

            let preimage_bytes = self.redundancy_function(&prefixless, prefix)
                .unwrap();
            
            let preimage: String = preimage_bytes
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect();
            
            let preimage_hash = &self.state.hash_message(
                &preimage_bytes
            );
            let truncated_preimage_hash = self.truncate_hash(&preimage_hash);

            if *hash != truncated_preimage_hash {
                return None;
            }

            let found_messagehash = MessageHash::new(
                &preimage,
                preimage_hash.clone()
            );

            println!(
                "[SUCCESS] Found preimage on iteration {}!\n{}\n{}\n",
                iteration,
                self.state.messagehash(),
                found_messagehash
            );

            return Some(preimage);
        }
        else {
            *value = self.calculate_last_value(1, value, prefix)
                .unwrap();
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
        
        let tables = self.create_preprocessing_tables(&running);

        if tables.is_empty() {
            return AttackResult::Failure;
        }
        
        println!("[INFO] Searching for a preimage...");

        let messagehash = self.state.messagehash();
        let hash = self.truncate_hash(messagehash.hash_value());
        let mut values: Vec<Vec<u8>> = vec![
            hash.clone(); self.tables_num as usize
        ];

        let mut j = 1;

        while j <= self.iteration_count {
            if !running.load(Ordering::SeqCst) {
                println!("[INFO] Attack terminated after {} iterations", j);
                break;
            }
            
            for (i, (table, prefix)) in tables.iter().enumerate() {
                if let Some(preimage) = self.try_find_value(
                    &hash,
                    table,
                    prefix,
                    &mut values[i],
                    j
                ) {
                    return AttackResult::Preimage(preimage);
                }
            }

            j += 1;
        }

        println!("[FAILURE] Preimage was not found in {} iterations\n", j - 1);
        
        AttackResult::Failure
    }
}
