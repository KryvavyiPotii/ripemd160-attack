use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use rand::prelude::*;

use super::{AttackResult, AttackState, HashAttack};
use crate::messagehash::{HashValue, MessageHash, HASH_SIZE_IN_BYTES};


const REDUNDANCY_OUTPUT_SIZE_IN_BYTES: usize = 16;
const TRUNCATED_HASH_SIZE_IN_BYTES: usize = 2;
const REDUNDANCY_PREFIX_SIZE_IN_BYTES: usize =
    REDUNDANCY_OUTPUT_SIZE_IN_BYTES - TRUNCATED_HASH_SIZE_IN_BYTES;
const TRUNCATED_HASH_INDEX_IN_BYTES: usize =
    HASH_SIZE_IN_BYTES - TRUNCATED_HASH_SIZE_IN_BYTES;


type Prefix = [u8; REDUNDANCY_PREFIX_SIZE_IN_BYTES];
type RedundantValue = [u8; REDUNDANCY_OUTPUT_SIZE_IN_BYTES]; 
type TruncatedHash = [u8; TRUNCATED_HASH_SIZE_IN_BYTES];
type PreprocessingTable = Vec<(TruncatedHash, TruncatedHash)>;


fn generate_redundancy_prefix() -> Prefix {
    let mut rng = thread_rng();

    rng.gen()
}

fn redundancy_function(
    hash: &TruncatedHash,
    prefix: &Prefix
) -> RedundantValue {
    let mut result = [0; REDUNDANCY_OUTPUT_SIZE_IN_BYTES];
    
    result[..REDUNDANCY_PREFIX_SIZE_IN_BYTES].copy_from_slice(prefix);
    result[REDUNDANCY_PREFIX_SIZE_IN_BYTES..].copy_from_slice(hash);

    result
}

fn truncate_hash(hash_value: &HashValue) -> TruncatedHash {
    let mut truncated_hash = [0; TRUNCATED_HASH_SIZE_IN_BYTES];
        
    truncated_hash.copy_from_slice(
        &hash_value[TRUNCATED_HASH_INDEX_IN_BYTES..]
    );

    truncated_hash
}


pub struct Hellman {
    state: AttackState,
    tables_num: u32,
    variable_number: u32,
    iteration_count: u32,
}

impl Hellman {
    pub fn new(
        initial_state: AttackState,
        tables_num: u32,
        variable_number: u32,
        iteration_count: u32
    ) -> Self {
        Self {
            state: initial_state,
            tables_num,
            variable_number,
            iteration_count
        }
    }

    fn calculate_last_value(
        &mut self,
        iteration_count: u32,
        first_value: &TruncatedHash,
        prefix: &Prefix
    ) -> TruncatedHash {
        let mut last_value = first_value.clone();
        
        for _ in 1..=iteration_count {
            let redundant_value = redundancy_function(&last_value, prefix);
            let hash = &self.state.hash_message(&redundant_value);

            last_value = truncate_hash(&hash);
        }

        last_value
    }

    fn create_preprocessing_table(
        &mut self, 
        running: &Arc<AtomicBool>
    ) -> (PreprocessingTable, Prefix) {
        let mut table = Vec::new();
        let mut rng = thread_rng(); 
        let prefix = generate_redundancy_prefix();

        for i in 1..=self.variable_number {
            if !running.load(Ordering::SeqCst) {
                println!(
                    "[INFO] Table generation terminated after {} iterations",
                    i
                );
                break;
            }
            
            let first_value: TruncatedHash = rng.gen();
            let last_value = self.calculate_last_value(
                self.iteration_count,
                &first_value, 
                &prefix
            );

            table.push((first_value, last_value));
        }

        (table, prefix)
    }

    fn create_preprocessing_tables(
        &mut self,
        running: &Arc<AtomicBool>
    ) -> Vec<(PreprocessingTable, Prefix)> {
        let mut tables = Vec::new();
        
        for i in 1..=self.tables_num {
            if !running.load(Ordering::SeqCst) {
                println!("[INFO] Table {} generation terminated", i);
                break;
            }
            
            tables.push(self.create_preprocessing_table(&running));

            println!("[INFO] Table {} created", i);
        }

        tables
    }

    fn try_find_value(
        &mut self,
        hash: &TruncatedHash,
        table: &PreprocessingTable,
        prefix: &Prefix,
        value: &mut TruncatedHash,
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
            );

            let preimage_bytes = redundancy_function(&prefixless, prefix);
            
            let preimage: String = preimage_bytes
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect();
            
            let preimage_hash = &self.state.hash_message(
                &preimage_bytes
            );
            let truncated_preimage_hash = truncate_hash(&preimage_hash);

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
            *value = self.calculate_last_value(1, value, prefix);
        } 

        None
    }
}

impl HashAttack for Hellman {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        let tables = self.create_preprocessing_tables(&running);

        if tables.is_empty() {
            return AttackResult::Failure;
        }

        let hash = truncate_hash(self.state.messagehash().hash_value());
        let mut values: Vec<TruncatedHash> = vec![
            hash; self.tables_num as usize
        ];

        for j in 1..=self.iteration_count {
            if !running.load(Ordering::SeqCst) {
                println!("[INFO] Attack terminated after {} iterations", j);
                break;
            }
            
            println!("[INFO] Attack iteration {}", j);
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
        }

        AttackResult::Failure
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::messagetransform::MessageTransform;

    #[test]
    fn hash_redundancy_one_by_one() {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc_async::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
        
        let initial_state = AttackState::new(
           "test",
           MessageTransform::AppendRandomNumber
        );

        let mut hellman = Hellman::new(
            initial_state,
            1,
            1 << 14,
            1 << 7
        );
        
        let (table, prefix) = hellman.create_preprocessing_table(&running);

        let first = table[0].0.clone();
        let single_middle = hellman.calculate_last_value(5, &first, &prefix);
        let mut loop_middle = first.clone();

        for _ in 1..=5 {
            loop_middle = hellman.calculate_last_value(
                1,
                &loop_middle,
                &prefix
            );
        }

        assert_eq!(loop_middle, single_middle);
    }

    #[test]
    fn different_prefixes() {
        let mut rng = thread_rng();

        let x: TruncatedHash = rng.gen();
        let prefix1 = generate_redundancy_prefix();
        let prefix2 = generate_redundancy_prefix();

        let redundant1 = redundancy_function(&x, &prefix1);
        let redundant2 = redundancy_function(&x, &prefix2);

        assert_ne!(redundant1, redundant2);
    }
}
