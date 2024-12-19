use std::{
    fs,
    path::Path,
    sync::{atomic::{AtomicBool, Ordering}, Arc},
};

use rand::prelude::*;
use serde::{Serialize, Deserialize};

use crate::messagehash::{HashValue, MessageHash};

use super::{AttackLog, AttackResult, AttackState, HashAttack};


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

// TODO change to a macros
fn make_table_filepath(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    chain_number: u64,
    iteration_count: u64,
    table_index: usize
) -> String {
    format!(
        "{}/{}/{}/table-{}-{}_{}",
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        chain_number,
        iteration_count,
        table_index
    )
}

fn parse_filepath(
    filepath: &str
) -> Result<(usize, usize, u64, u64), &'static str> {
    let fs_parts: Vec<&str> = filepath
        .split(&['/', '\\'][..])
        .collect();
    
    let path_length = fs_parts.len();
    if path_length < 4 {
        return Err("Invalid filepath");
    }

    // Using reverse indexes to allow directory_path of any length.
    let hash_size_in_bytes = fs_parts[path_length - 3].parse()
        .expect("Failed to parse hash size");
    let reduction_prefix_size_in_bytes = fs_parts[path_length - 2].parse()
        .expect("Failed to parse reduction function output size");
    
    let parts: Vec<&str> = fs_parts[path_length - 1]
        .split(&['-', '_'][..])
        .collect();
    
    if parts.len() != 4 {
        return Err("Invalid filepath");
    }

    let chain_number = parts[1].parse()
        .expect("Failed to parse chain number");
    let iteration_count = parts[2].parse()
        .expect("Failed to parse iteration count");

    Ok((
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        chain_number,
        iteration_count
    ))
}

fn is_right_path(
    filepath: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    chain_number: u64,
    iteration_count: u64,
) -> bool {
    let (
        parsed_hash_size,
        parsed_reduction_prefix_size,
        parsed_chain_number,
        parsed_iteration_count
    ) = match parse_filepath(filepath) {
        Ok(parsed_values) => parsed_values,
        Err(_) => return false,
    };

    if hash_size_in_bytes != parsed_hash_size {
        return false;
    }
    if reduction_prefix_size_in_bytes != parsed_reduction_prefix_size {
        return false;
    }
    // Allow reading bigger tables.
    if chain_number > parsed_chain_number {
        return false;
    }
    if iteration_count != parsed_iteration_count {
        return false;
    }

    true
}

fn create_output_directory(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
) {
    let path = format!(
        "{}/{}/{}",
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes
    );

    if !Path::new(&path).exists() {
        let _ = fs::create_dir_all(&path);
    }
}

fn read_filepaths(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    chain_number: u64,
    iteration_count: u64,
    tables_number: usize
) -> Result<Vec<String>, &'static str> {
    let directory = fs::read_dir(
        format!(
            "{}/{}/{}",
            directory_path,
            hash_size_in_bytes,
            reduction_prefix_size_in_bytes
        ))
        .expect("Failed to open tables directory");

    let all_filepaths: Vec<String> = directory
        .map(|entry| {
            let entry = entry
                .expect("Invalid entry");

            let path = entry
                .path()
                .into_os_string()
                .into_string()
                .expect("Failed to convert PathBuf to String");

            path
        })
        .collect();

    let proper_filepaths: Vec<String> = all_filepaths
        .iter()
        .filter(|path| { 
            is_right_path(
                &path,
                hash_size_in_bytes,
                reduction_prefix_size_in_bytes,
                chain_number,
                iteration_count
            )
        })
        .map(|path| path.to_string())
        .take(tables_number)
        .collect();

    Ok(proper_filepaths)
}

fn bytes_to_string(bytes: &Vec<u8>) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}


#[derive(Debug, Deserialize, Serialize, Clone)]
struct Chain(Vec<u8>, Vec<u8>);

impl Chain { 
    fn new(first_point: Vec<u8>, last_point: Vec<u8>) -> Self {
        Self(first_point, last_point)
    }
}


#[derive(Debug, Deserialize, Serialize)]
struct Table {
    entries: Vec<Chain>,
    prefix: Vec<u8>
}

impl Table {
    fn new(entries: Vec<Chain>, prefix: Vec<u8>) -> Self {
        Self { entries, prefix }
    }

    fn from_file(
        filepath: &str,
        entries_number: usize
    ) -> Result<Self, &'static str> {
        let json: String = fs::read_to_string(filepath)
            .expect("Failed to read file");
        
        let mut table: Table = serde_json::from_str(&json)
            .expect("Failed to deserialize");

        table.entries.truncate(entries_number);

        Ok(table)
    }

    fn push(&mut self, entry: Chain) {
        self.entries.push(entry);
    }

    fn sort(&mut self) {
        self.entries
            .sort_by(|a, b| a.1.cmp(&b.1));
    }

    fn search_by_last_point(&self, point: &Vec<u8>) -> Option<&Chain> {
        if let Ok(index) = self.entries
            .binary_search_by(|entry| entry.1.cmp(&point))
        {
            Some(&self.entries[index])
        }
        else {
            None
        }
    }

    fn store_table(&self, filepath: &str) -> Result<(), &'static str> {
        let json = serde_json::to_string(self).unwrap();

        fs::write(filepath, json)
            .expect("Failed to write file");

        Ok(())
    }
}


pub enum TableNumber {
    Execute(usize, usize),
    Generate(usize)
}

impl TableNumber {
    fn on_disk(&self) -> usize {
        match self {
            Self::Execute(number, _) => *number,
            Self::Generate(number) => *number
        }
    }

    fn in_memory(&self) -> usize {
        match self {
            Self::Execute(_, number) => *number,
            Self::Generate(_) => 0
        }
    }
}

impl From<usize> for TableNumber {
    fn from(tables_number: usize) -> Self {
        Self::Generate(tables_number)
    }
}

impl From<(usize, usize)> for TableNumber {
    fn from(numbers: (usize, usize)) -> Self {
        let (tables_number, memory_tables_number) = numbers;

        Self::Execute(tables_number, memory_tables_number)
    }
}


pub struct Hellman {
    state: AttackState,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    tables_number: TableNumber,
    chain_number: u64,
    iteration_count: u64,
    table_directory_path: String
}

impl Hellman {
    pub fn build(
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        reduction_output_size_in_bytes: usize,
        tables_number: TableNumber,
        chain_number: u64,
        iteration_count: u64,
        table_directory_path: &str
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

        let reduction_prefix_size_in_bytes =
            reduction_output_size_in_bytes - hash_size_in_bytes; 
        let table_directory_path = table_directory_path.to_string();

        Ok(
            Self {
                state: initial_state,
                hash_size_in_bytes,
                reduction_prefix_size_in_bytes,
                tables_number,
                chain_number,
                iteration_count,
                table_directory_path
            }
        )
    }
    
    fn calculate_last_point(
        &mut self,
        iteration_count: u64,
        first_point: &Vec<u8>,
        prefix: &Vec<u8>
    ) -> Vec<u8> {
        let mut last_point = first_point.clone();

        for _ in 1..=iteration_count {
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
                AttackLog::Term(
                    "Hellman.create_preprocessing_table",
                    i.into()
                ).log();
                break;
            }
            
            let first_point = generate_random_byte_vector(
                self.hash_size_in_bytes
            );
            let last_point = self.calculate_last_point(
                self.iteration_count,
                &first_point, 
                &table.prefix
            );

            let entry = Chain::new(first_point, last_point);

            table.push(entry);
        }

        table
    }

    pub fn generate(&mut self) {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc_async::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
     
        create_output_directory(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes
        );
       
        AttackLog::TableGenInit(self.tables_number.on_disk()).log();
    
        let mut j = 0;

        for i in 1..=self.tables_number.on_disk() {
            if !running.load(Ordering::SeqCst) {
                AttackLog::Term("Hellman.generate", i.into()).log();
                return;
            }
            
            let mut table = self.create_preprocessing_table(&running);
          
            // Sort the table by last points for future binary search.
            table.sort();

            let mut filepath = make_table_filepath(
                &self.table_directory_path,
                self.hash_size_in_bytes,
                self.reduction_prefix_size_in_bytes,
                self.chain_number,
                self.iteration_count,
                i
            );

            while Path::new(&filepath).exists() {
                filepath = make_table_filepath(
                    &self.table_directory_path,
                    self.hash_size_in_bytes,
                    self.reduction_prefix_size_in_bytes,
                    self.chain_number,
                    self.iteration_count,
                    i + j
                );

                j += 1;
            }

            table.store_table(&filepath)
                .expect("Failed to write table to disk");
           
            AttackLog::TableGenSuccess(&filepath).log();
        }
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
            let prefixless = self.calculate_last_point(
                self.iteration_count - iteration,
                first_point,
                &table.prefix
            );

            let preimage_bytes = reduction_function(
                &prefixless, 
                &table.prefix
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
        else {
            *point = self.calculate_last_point(
                1, 
                &point.clone(), 
                &table.prefix
            );
        } 

        None
    }
}

impl HashAttack for Hellman {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        AttackLog::Init(&self.state.messagehash()).log();
      
        let filepaths = read_filepaths(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes,
            self.chain_number,
            self.iteration_count,
            self.tables_number.on_disk()
        ).expect("Failed to read table directory contents");
        
        let messagehash = self.state.messagehash();
        let hash = truncate_hash(
            messagehash.hash_value(),
            self.hash_size_in_bytes
        ); 
        let mut points = vec![hash.clone(); filepaths.len()];

        let mut total_iterations: u64 = 0;
        let mut iteration: u64 = 1;
        let mut result = AttackResult::Failure; 
        let memory_tables_number = self.tables_number.in_memory();

        for i in (0..filepaths.len()).step_by(memory_tables_number) {
            let current_filepaths = filepaths
                .iter()
                .skip(i)
                .take(memory_tables_number);

            // Read tables_number tables into memory.
            let tables: Vec<Table> = current_filepaths.clone()
                .map(|path| 
                    Table::from_file(path, self.chain_number as usize)
                        .expect("Failed to deserialize table")
                )
                .collect();

            // Process tables in memory.
            while iteration <= self.iteration_count {
                if !running.load(Ordering::SeqCst) {
                    AttackLog::Term("Hellman.attack", iteration.into()).log();
                    break;
                }

                // TODO add multithreading
                for (j, table) in tables.iter().enumerate() {
                    if let Some(preimage) = self.try_find_point(
                        &hash,
                        &table,
                        &mut points[i + j],
                        iteration
                    ) {
                        result = AttackResult::Preimage(preimage);
                        
                        AttackLog::PerTableResult(
                            &result,
                            &filepaths[i + j],
                            iteration.into()
                        ).log();

                        return result;
                    }
                }     
                
                iteration += 1;
            }   

            for filepath in current_filepaths {
                AttackLog::PerTableResult(
                    &AttackResult::Failure,
                    filepath,
                    (iteration - 1).into()
                ).log();
            }

            total_iterations += (iteration - 1) * tables.len() as u64;
            iteration = 1;
        }
     
        AttackLog::Result(
            &result,
            total_iterations.into()
        ).log();

        result
    }
}
