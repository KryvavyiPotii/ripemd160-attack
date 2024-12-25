use std::{
    fs, 
    io::Write,
    path::{Path, PathBuf}
};

use serde::{Serialize, Deserialize};


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Chain(pub Vec<u8>, pub Vec<u8>);

impl Chain { 
    pub fn new(first_point: Vec<u8>, last_point: Vec<u8>) -> Self {
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
pub struct Table {
    chains: Vec<Chain>,
    prefix: Vec<u8>
}

impl Table {
    pub fn new(chains: Vec<Chain>, prefix: Vec<u8>) -> Self {
        Self { chains, prefix }
    }

    pub fn prefix(&self) -> &Vec<u8> {
        &self.prefix
    }

    // TODO add support for reading files of different formats and 
    // chains numbers:
    // (..., formats: Vec<&str>, chain_numbers: Vec<usize>) or
    // HashMap
    pub fn from_files(
        filepaths: &[PathBuf],
        format: &str,
        chain_number: usize
    ) -> Vec<Self> {
        filepaths
            .iter()
            .map(|path| 
                Table::from_file(
                    path,
                    format,
                    chain_number
                ).expect("Failed to deserialize table")
            )
            .collect()
    }

    pub fn from_file(
        filepath: &Path,
        format: &str,
        chain_number: usize
    ) -> Result<Self, &'static str> {
        match format {
            "json" => Self::from_json(filepath, chain_number),
            "bin" => Self::from_bin(filepath, chain_number),
            _ => return Err("Invalid file format")
        }
    }

    fn from_json(
        filepath: &Path,
        chain_number: usize
    ) -> Result<Self, &'static str> {
        let json: String = fs::read_to_string(filepath)
            .expect("Failed to read file");
        
        let mut table: Table = serde_json::from_str(&json)
            .expect("Failed to deserialize");

        table.chains.truncate(chain_number);

        Ok(table)
    }

    fn from_bin(
        filepath: &Path,
        chain_number: usize
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
        let parsed_chain_number = u32::from_be_bytes(
            raw_chain_number
        ) as usize;

        // If maximum value of usize is past, read the whole table.
        let chain_number = if chain_number == usize::max_value() {
            parsed_chain_number
        }
        else {
            chain_number
        };
        
        if chain_number > parsed_chain_number as usize {
            return Err("Table does not have enough chains");
        }
        
        let prefix_index = 6 + parsed_chain_number * chain_size_in_bytes;
        
        let chains: Vec<Chain> = (6..prefix_index)
            .take(chain_number * chain_size_in_bytes)
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

    pub fn to_file(
        &self,
        filepath: &Path,
        format: &str
    ) -> Result<(), &'static str> {
        let _ = match format {
            "json" => self.to_json(filepath),
            "bin" => self.to_bin(filepath),
            _ => Err("Invalid file format")
        };

        Ok(())
    }

    fn to_json(&self, filepath: &Path) -> Result<(), &'static str> {
        let json = serde_json::to_string(self).unwrap();

        fs::write(filepath, json)
            .expect("Failed to write file");

        Ok(())
    }

    fn to_bin(&self, filepath: &Path) -> Result<(), &'static str> {
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

    pub fn push(&mut self, entry: Chain) {
        self.chains.push(entry);
    }

    pub fn sort(&mut self) {
        self.chains
            .sort_by(|a, b| a.1.cmp(&b.1));
    }

    pub fn search_by_last_point(&self, point: &Vec<u8>) -> Option<&Chain> {
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
    pub fn on_disk(&self) -> usize {
        match self {
            Self::Execute(number, _) => *number,
            Self::Generate(number) => *number
        }
    }

    pub fn in_memory(&self) -> usize {
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
