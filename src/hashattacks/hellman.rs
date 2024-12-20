use std::{
    fs, 
    io::Write, 
    sync::{atomic::{AtomicBool, Ordering}, Arc}
};

use rand::prelude::*;
use serde::{Serialize, Deserialize};

use crate::messagehash::{HashValue, MessageHash};
use tableio::*;

use super::{AttackLog, AttackResult, AttackState, HashAttack};


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


#[derive(Debug, Deserialize, Serialize, Clone)]
struct Chain(Vec<u8>, Vec<u8>);

impl Chain { 
    fn new(first_point: Vec<u8>, last_point: Vec<u8>) -> Self {
        Self(first_point, last_point)
    }
}

impl TryFrom<&[u8]> for Chain {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Chain must consist of two points of the same size.
        if bytes.len() % 2 != 0 {
            return Err("Invalid data");
        }
        
        let point_size_in_bytes = bytes.len() / 2;
        
        let first_point = Vec::from(
            bytes
                .get(..point_size_in_bytes)
                .expect("Failed to parse first chain point")
        );
        let last_point = Vec::from(
            bytes
                .get(point_size_in_bytes..)
                .expect("Failed to parse last chain point")
        );

        let chain = Self::new(first_point, last_point);

        Ok(chain)
    }
}


#[derive(Debug, Deserialize, Serialize)]
struct Table {
    chains: Vec<Chain>,
    prefix: Vec<u8>
}

impl Table {
    fn new(chains: Vec<Chain>, prefix: Vec<u8>) -> Self {
        Self { chains, prefix }
    }

    // TODO converter from json to bin and vice versa
    fn from_file(
        filepath: &str,
        format: &str,
        chains_number: usize
    ) -> Result<Self, &'static str> {
        match format {
            "json" => Self::from_json(filepath, chains_number),
            "bin" => Self::from_bin(filepath, chains_number),
            _ => return Err("Invalid file format")
        }
    }

    // TODO improve json deserialization ("b8a2" -> "[[184,162]]")
    fn from_json(
        filepath: &str,
        chains_number: usize
    ) -> Result<Self, &'static str> {
        let json: String = fs::read_to_string(filepath)
            .expect("Failed to read file");
        
        let mut table: Table = serde_json::from_str(&json)
            .expect("Failed to deserialize");

        table.chains.truncate(chains_number);

        Ok(table)
    }

    fn from_bin(
        filepath: &str,
        chains_number: usize
    ) -> Result<Self, &'static str> {
        let data: Vec<u8> = fs::read(filepath)
            .expect("Failed to read file");

        let raw_hash_size: [u8; 2] = data
            .get(0..=1)
            .expect("Invalid data")
            .try_into()
            .expect("Failed to parse hash size");
        let point_size_in_bytes = u16::from_be_bytes(raw_hash_size) as usize;

        let chain_size_in_bytes = point_size_in_bytes * 2;

        let raw_chain_number: [u8; 4] = data
            .get(2..=5)
            .expect("Invalid data")
            .try_into()
            .expect("Failed to parse chain number");
        let parsed_chains_number = u32::from_be_bytes(
            raw_chain_number
        ) as usize;

        // If maximum value of usize is past, read the whole table.
        let chains_number = if chains_number == usize::max_value() {
            parsed_chains_number
        }
        else {
            chains_number
        };
        
        if chains_number > parsed_chains_number as usize {
            return Err("Table does not have enough chains");
        }
        
        let prefix_index = 6 + parsed_chains_number * chain_size_in_bytes;
        
        let chains: Vec<Chain> = (6..prefix_index)
            .take(chains_number * chain_size_in_bytes)
            .step_by(chain_size_in_bytes)
            .map(|i| {
                Chain::try_from(
                    data
                        .get(i..(i + chain_size_in_bytes))
                        .expect("Invalid data")
                ).expect("Failed to convert bytes to chain")
            })
            .collect();

        let prefix = Vec::from(
            data
                .get(prefix_index..)
                .expect("Failed to parse first chain point")
        );

        let table = Self::new(chains, prefix);

        Ok(table)
    }

    fn to_file(
        &self,
        filepath: &str,
        format: &str
    ) -> Result<(), &'static str> {
        let _ = match format {
            "json" => self.to_json(filepath),
            "bin" => self.to_bin(filepath),
            _ => Err("Invalid file format")
        };

        Ok(())
    }

    // TODO improve json serialization ("[[184,162]]" -> "b8a2")
    fn to_json(&self, filepath: &str) -> Result<(), &'static str> {
        let json = serde_json::to_string(self).unwrap();

        fs::write(filepath, json)
            .expect("Failed to write file");

        Ok(())
    }

    fn to_bin(&self, filepath: &str) -> Result<(), &'static str> {
        // File format:
        // * 1-2 bytes - point size in bytes
        // * 3-6 bytes - number of chains in table
        // * 7-(7 + chain_number * hash_size * 2) bytes - chains
        // * bytes that are left - prefix
        let chain_number: u32 = self.chains.len() as u32;

        if chain_number == 0 {
            return Err("Table is empty");
        }

        let point_size_in_bytes: u16 = self.chains
            .get(0)
            .unwrap()
            .0.len() as u16;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(filepath)
            .expect("Failed to create file");

        file.write_all(&point_size_in_bytes.to_be_bytes())
            .expect("Failed to write hash size");
        file.write_all(&chain_number.to_be_bytes())
            .expect("Failed to write number of chains");

        for chain in &self.chains {
            file.write_all(&chain.0)
                .expect("Failed to write first chain point");
            file.write_all(&chain.1)
                .expect("Failed to write last chain point");
        }

        file.write_all(&self.prefix)
            .expect("Failed to write reduction prefix");

        Ok(())
    }

    fn push(&mut self, entry: Chain) {
        self.chains.push(entry);
    }

    fn sort(&mut self) {
        self.chains
            .sort_by(|a, b| a.1.cmp(&b.1));
    }

    fn search_by_last_point(&self, point: &Vec<u8>) -> Option<&Chain> {
        if let Ok(index) = self.chains
            .binary_search_by(|entry| entry.1.cmp(&point))
        {
            Some(&self.chains[index])
        }
        else {
            None
        }
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
    chain_length: u64,
    table_directory_path: String,
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
        table_directory_path: &str,
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
        let table_directory_path = table_directory_path.to_string();
        let table_file_format = table_file_format.to_string(); 

        Ok(
            Self {
                state: initial_state,
                hash_size_in_bytes,
                reduction_prefix_size_in_bytes,
                tables_number,
                chain_number,
                chain_length,
                table_directory_path,
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
                self.chain_length,
                &first_point, 
                &table.prefix
            );

            let entry = Chain::new(first_point, last_point);

            table.push(entry);
        }

        table
    }

    // Helper function.
    fn table_filepath(&self, file_format: &str, table_index: usize) -> String {
        make_table_filepath(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes,
            file_format,
            self.chain_number,
            self.chain_length,
            table_index
        )
    }

    // Helper function.
    fn table_free_filepath(
        &self,
        output_format: &str, 
        start_index: usize
    ) -> String {
        get_free_filepath(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes,
            output_format,
            self.chain_number,
            self.chain_length,
            start_index
        )
    }
    
    // Helper function.
    fn table_free_index(
        &self, 
        output_format: &str, 
        start_index: usize
    ) -> usize {
        get_free_index(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes,
            output_format,
            self.chain_number,
            self.chain_length,
            start_index
        )
    }

    pub fn generate(&mut self) -> Result<(), &'static str> {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc_async::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
     
        create_output_directory(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes,
            &self.table_file_format
        );
       
        AttackLog::TableGenInit(self.tables_number.on_disk()).log();
    
        let mut j = 1;

        for i in 1..=self.tables_number.on_disk() {
            if !running.load(Ordering::SeqCst) {
                AttackLog::Term("Hellman.generate", i.into()).log();
                return Ok(());
            }
            
            let mut table = self.create_preprocessing_table(&running);
          
            // Sort the table by last points for future binary search.
            table.sort();

            j = self.table_free_index(&self.table_file_format, j);

            let filepath = self.table_filepath(&self.table_file_format, j);

            table.to_file(&filepath, &self.table_file_format)?;
           
            AttackLog::TableGenSuccess(&filepath).log();
        }

        Ok(())
    }

    pub fn convert(
        &self,
        output_format: &str,
        table_index: usize,
        force: bool
    ) -> Result<(), &'static str> {
        let mut filepath = self.table_filepath(
            &self.table_file_format,
            table_index
        );

        let table_in = match Table::from_file(
            &filepath, 
            &self.table_file_format, 
            usize::max_value()
        ) {
            Ok(table) => table,
            Err(e) => {
                AttackLog::TableFailure(&filepath, 1u64.into());
                return Err(e);
            }
        };
        
        // Choose whether to keep table index in converted table.
        // Table with the same index will be overwritten.
        filepath = if force {
            self.table_filepath(output_format, table_index)
        }
        else {
            self.table_free_filepath(output_format, 1)
        };

        match table_in.to_file(&filepath, output_format) {
            Ok(_) => (),
            Err(e) => {
                AttackLog::TableFailure(&filepath, 2u64.into());
                return Err(e);
            }
        };

        AttackLog::TableGenSuccess(&filepath).log();

        Ok(())
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
                self.chain_length - iteration,
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
    fn attack(
        &mut self,
        running: Arc<AtomicBool>
    ) -> Result<AttackResult, &'static str> {
        AttackLog::Init(&self.state.messagehash()).log();
      
        let filepaths = read_table_filepaths(
            &self.table_directory_path,
            self.hash_size_in_bytes,
            self.reduction_prefix_size_in_bytes,
            &self.table_file_format,
            self.chain_number,
            self.chain_length,
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
        let memory_tables_number = self.tables_number.in_memory();

        for i in (0..filepaths.len()).step_by(memory_tables_number) {
            let current_filepaths = filepaths
                .iter()
                .skip(i)
                .take(memory_tables_number);

            // Read tables_number tables into memory.
            let tables: Vec<Table> = current_filepaths.clone()
                .map(|path| 
                    Table::from_file(
                        path,
                        &self.table_file_format,
                        self.chain_number as usize
                    ).expect("Failed to deserialize table")
                )
                .collect();

            // Process tables in memory.
            while iteration <= self.chain_length {
                if !running.load(Ordering::SeqCst) {
                    AttackLog::Term("Hellman.attack", iteration.into()).log();
                    return Err("Attack terminated");
                }

                // TODO add multithreading
                for (j, table) in tables.iter().enumerate() {
                    if let Some(preimage) = self.try_find_point(
                        &hash,
                        &table,
                        &mut points[i + j],
                        iteration
                    ) {
                        let result = AttackResult::Preimage(preimage);
                        
                        AttackLog::TableSuccess(
                            &result,
                            &filepaths[i + j],
                            iteration.into()
                        ).log();

                        return Ok(result);
                    }
                }     
                
                iteration += 1;
            }   

            for filepath in current_filepaths {
                AttackLog::TableFailure(
                    filepath,
                    (iteration - 1).into()
                ).log();
            }

            total_iterations += (iteration - 1) * tables.len() as u64;
            iteration = 1;
        }
     
        AttackLog::Failure(total_iterations.into()).log();

        Err("Attack failed")
    }
}
