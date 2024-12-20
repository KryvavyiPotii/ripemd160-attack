use std::{fs, path::Path};


// TODO change to a macros
pub fn make_table_filepath(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
    chain_number: u64,
    chain_length: u64,
    table_index: usize
) -> String {
    format!(
        "{}/{}/{}/{}/table-{}-{}_{}",
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format,
        chain_number,
        chain_length,
        table_index
    )
}

pub fn get_free_index(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
    chain_number: u64,
    chain_length: u64,
    start_index: usize
) -> usize {
    let mut j = start_index;
    let mut filepath = make_table_filepath(
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format,
        chain_number,
        chain_length,
        j
    );

    while Path::new(&filepath).exists() {
        j += 1;

        filepath = make_table_filepath(
            directory_path,
            hash_size_in_bytes,
            reduction_prefix_size_in_bytes,
            table_file_format,
            chain_number,
            chain_length,
            j
        );
    }

    j
}

pub fn get_free_filepath(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
    chain_number: u64,
    chain_length: u64,
    start_index: usize
) -> String {
    let free_index = get_free_index(
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format,
        chain_number,
        chain_length,
        start_index
    );

    make_table_filepath(
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format,
        chain_number,
        chain_length,
        free_index
    )
}

fn make_table_directory_path(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
) -> String {
    format!(
        "{}/{}/{}/{}",
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format
    )
}

pub fn parse_filepath(
    filepath: &str
) -> Result<(usize, usize, String, u64, u64), &'static str> {
    // Parse parent directories.
    let fs_parts: Vec<&str> = filepath
        .split(&['/', '\\'][..])
        .collect();
    
    let path_length = fs_parts.len();
    if path_length < 5 {
        return Err("Invalid filepath");
    }

    // Using reverse indexes to allow directory_path of any length.
    let hash_size_in_bytes = fs_parts[path_length - 4].parse()
        .expect("Failed to parse hash size");
    let reduction_prefix_size_in_bytes = fs_parts[path_length - 3].parse()
        .expect("Failed to parse reduction function output size");
    let table_file_format = fs_parts[path_length - 2];

    match table_file_format {
        "json" | "bin" => (),
        _ => return Err("Failed to parse reduction function output size")
    }
   
    // Parse file name.
    let parts: Vec<&str> = fs_parts[path_length - 1]
        .split(&['-', '_'][..])
        .collect();
    
    if parts.len() != 4 {
        return Err("Invalid filepath");
    }

    let chain_number = parts[1].parse()
        .expect("Failed to parse chain number");
    let chain_length = parts[2].parse()
        .expect("Failed to parse iteration count");

    Ok((
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format.to_string(),
        chain_number,
        chain_length
    ))
}

pub fn is_right_path(
    filepath: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
    chain_number: u64,
    chain_length: u64,
) -> bool {
    let (
        parsed_hash_size,
        parsed_reduction_prefix_size,
        parsed_table_file_format,
        parsed_chain_number,
        parsed_chain_length
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
    if table_file_format != parsed_table_file_format {
        return false;
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

pub fn create_output_directory(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
) {
    let path = make_table_directory_path(
        directory_path,
        hash_size_in_bytes,
        reduction_prefix_size_in_bytes,
        table_file_format
    );

    if !Path::new(&path).exists() {
        let _ = fs::create_dir_all(&path);
    }
}

pub fn read_table_filepaths(
    directory_path: &str,
    hash_size_in_bytes: usize,
    reduction_prefix_size_in_bytes: usize,
    table_file_format: &str,
    chain_number: u64,
    chain_length: u64,
    tables_number: usize
) -> Result<Vec<String>, &'static str> {
    match table_file_format {
        "json" | "bin" => (),
        _ => return Err("Invalid file format")
    };

    let directory = fs::read_dir(
        make_table_directory_path(
            directory_path,
            hash_size_in_bytes,
            reduction_prefix_size_in_bytes,
            table_file_format
        )
    ).expect("Failed to open tables directory");

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
                &table_file_format,
                chain_number,
                chain_length
            )
        })
        .map(|path| path.to_string())
        .take(tables_number)
        .collect();

    Ok(proper_filepaths)
}
