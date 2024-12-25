use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf}
};


const PATH_PARTS: usize = 5;


#[derive(Clone)]
pub struct TableDirectory {
    pub root_directory_path: PathBuf,
    pub hash_size_in_bytes: usize,
    pub reduction_prefix_size_in_bytes: usize,
    pub table_file_format: String
}

impl TableDirectory {
    pub fn new(
        root_directory_path: &Path,
        hash_size_in_bytes: usize,
        reduction_prefix_size_in_bytes: usize,
        table_file_format: &str,
    ) -> Self {
        let root_directory_path = root_directory_path.to_path_buf();
        let table_file_format = table_file_format.to_string();

        Self {
            root_directory_path,
            hash_size_in_bytes,
            reduction_prefix_size_in_bytes,
            table_file_format
        }
    }

    pub fn path(&self) -> PathBuf {
        let mut directory_path = PathBuf::with_capacity(PATH_PARTS);

        directory_path.push(&self.root_directory_path);
        directory_path.push(self.hash_size_in_bytes.to_string());
        directory_path.push(self.reduction_prefix_size_in_bytes.to_string());
        directory_path.push(self.table_file_format.to_string());
        
        directory_path
    }

    // Create directory if it does not exist.
    pub fn create_directory(&self) {
        let path = self.path();

        if !path.exists() {
            let _ = fs::create_dir_all(&path);
        }
    }

    pub fn read_table_filepaths(
        &self,
        chain_number: u64,
        chain_length: u64,
        tables_number: usize
    ) -> Result<Vec<PathBuf>, &'static str> {
        let directory = fs::read_dir(&self.path())
            .expect("Failed to open tables directory");

        let all_filepaths: Vec<PathBuf> = directory
            .map(|entry| {
                let entry = entry
                    .expect("Invalid entry");
                
                entry.path()
            })
            .collect();

        let proper_filepaths: Vec<PathBuf> = all_filepaths
            .into_iter()
            .filter(|path|  
                Self::is_correct(
                    path,
                    chain_number,
                    chain_length
                )
            )
            .take(tables_number)
            .collect();

        Ok(proper_filepaths)
    }

    pub fn table_filepath(
        &self,
        chain_number: u64,
        chain_length: u64,
        table_index: usize
    ) -> PathBuf {
        let mut filepath = PathBuf::new();

        filepath.push(self.path());
        filepath.push(
            format!(
                "table-{}-{}_{}",
                chain_number,
                chain_length,
                table_index
            )
        );

        filepath
    }
    
    pub fn get_free_index(
        &self,
        chain_number: u64,
        chain_length: u64,
        start_index: usize
    ) -> usize {
        let mut table_index = start_index;
        let mut filepath = self.table_filepath(
            chain_number,
            chain_length,
            table_index
        );

        while filepath.exists() {
            table_index += 1;

            filepath = self.table_filepath(
                chain_number,
                chain_length,
                table_index
            );
        }

        table_index
    }
    
    pub fn get_free_filepath(
        &self,
        chain_number: u64,
        chain_length: u64,
        start_index: usize
    ) -> PathBuf {
        let free_index = self.get_free_index(
            chain_number,
            chain_length,
            start_index
        );

        self.table_filepath(
            chain_number,
            chain_length,
            free_index
        )
    }
 
    fn parse_filename(
        filename: &OsStr
    ) -> Result<(u64, u64, usize), &'static str> {
        let parts: Vec<&str> = filename
            .to_str()
            .expect("Failed to convert OsStr to &str")
            .split(&['-', '_'][..])
            .collect();

        let chain_number = parts[1].parse()
            .expect("Failed to parse chain number");
        let chain_length = parts[2].parse()
            .expect("Failed to parse chain length");
        let table_index = parts[3].parse()
            .expect("Failed to parse table index");

        Ok((chain_number, chain_length, table_index))
    }

    fn is_correct(
        filepath: &Path,
        chain_number: u64,
        chain_length: u64,
    ) -> bool {
        let (
            parsed_chain_number, 
            parsed_chain_length,
            _
        ) = match Self::parse_filename(
            filepath.file_name()
                .expect("File name is missing")
        ) {
            Ok(parsed_values) => parsed_values,
            Err(_) => return false,
        };

        // Allow reading bigger tables.
        if chain_number > parsed_chain_number {
            return false;
        }
        if chain_length != parsed_chain_length {
            return false;
        }

        true
    }
}
