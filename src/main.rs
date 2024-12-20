use std::process;

use clap::{Arg, ArgAction, Command};

use hashattacks::{*, messagetransform::*};

mod hashattacks;
mod messagehash;


const DEFAULT_MESSAGE: &str = "Some huge message";
const DEFAULT_VERBOSE_TRIES_NUMBER: &str = "30";
const DEFAULT_SUCCESS_PROBABILITY: &str  = "0.95";
const DEFAULT_HASH_SIZE_IN_BYTES: &str   = "2";

const DEFAULT_REDUCTION_OUTPUT_SIZE_IN_BYTES: &str = "16";
const DEFAULT_TABLE_DIRECTORY: &str                = "tables";
const DEFAULT_TABLE_FORMAT: &str                   = "bin";
const DEFAULT_GENERATED_TABLE_NUMBER: &str         = "1";
const DEFAULT_TABLE_NUMBER: &str                   = "1";
const DEFAULT_PROC_MEMORY_TABLE_NUMBER: &str       = "1";
const DEFAULT_CHAIN_NUMBER: &str                   = "16384";
const DEFAULT_CHAIN_LENGTH: &str                   = "128";

const ATTACK_BRUTEFORCE: &str = "bruteforce";
const ATTACK_BIRTHDAYS: &str  = "birthdays";
const ATTACK_HELLMAN: &str    = "hellman";
const HELLMAN_GENERATE: &str  = "generate";
const HELLMAN_CONVERT: &str   = "convert";
const HELLMAN_EXECUTE: &str   = "execute";

const TRANSFORM_RANDOM_NUMBER: &str      = "random_number";
const TRANSFORM_NUMBER_IN_SEQUENCE: &str = "number_in_sequence";
const TRANSFORM_MUTATE: &str             = "mutate";


fn main() {
    let matches = Command::new("ripemd160-attack")
        .version("0.5.4")
        .about("Execute various attacks on RIPEMD-160 hash.")
        .arg(
            Arg::new("message")
                .short('m')
                .long("message")
                .default_value(DEFAULT_MESSAGE)
                .help("Message to process")
        )
        .arg(
            Arg::new("message transform")
                .long("tr")
                .default_value(TRANSFORM_RANDOM_NUMBER)
                .value_parser([
                    TRANSFORM_RANDOM_NUMBER,
                    TRANSFORM_NUMBER_IN_SEQUENCE,
                    TRANSFORM_MUTATE
                ])
                .help("Type of message transformation")
        )
        .arg(
            Arg::new("hash size")
                .short('s')
                .long("hash-size")
                .default_value(DEFAULT_HASH_SIZE_IN_BYTES)
                .value_parser(clap::value_parser!(usize))
                .help("Size of the hash suffix in bytes that will be attacked")
        )
        .arg(
            Arg::new("success probability")
                .short('p')
                .long("probability")
                .default_value(DEFAULT_SUCCESS_PROBABILITY)
                .value_parser(clap::value_parser!(f32))
                .help("Expected success probability")
        )
        .arg(
            Arg::new("verbose tries")
                .long("verbose-tries")
                .default_value(DEFAULT_VERBOSE_TRIES_NUMBER)
                .value_parser(clap::value_parser!(u64))
                .help("Number of tries that will be printed out")
        )
        .subcommand(
            Command::new(ATTACK_BRUTEFORCE)
                .about("Execute brute-force attack")
        )
        .subcommand(
            Command::new(ATTACK_BIRTHDAYS)
                .about("Execute birthdays attack")
        )
        .subcommand(
            Command::new(ATTACK_HELLMAN)
                .about(
                    "Execute Hellman's attack or \
                    generates preprocessing table"
                )
                .arg(
                    Arg::new("table directory")
                        .short('d')
                        .long("table-dir")
                        .default_value(DEFAULT_TABLE_DIRECTORY)
                        .help("Path to table directory")
                )
                .arg(
                    Arg::new("table file format")
                        .long("format")
                        .default_value(DEFAULT_TABLE_FORMAT)
                        .value_parser(["json", "bin"])
                        .help("Table file format to read/write")
                )
                .arg(
                    Arg::new("reduction output size")
                        .long("rsize")
                        .default_value(DEFAULT_REDUCTION_OUTPUT_SIZE_IN_BYTES)
                        .value_parser(clap::value_parser!(usize))
                        .help("Reduction function output size in bytes")
                )
                .arg(
                    Arg::new("chain number")
                        .long("chain-num")
                        .default_value(DEFAULT_CHAIN_NUMBER)
                        .value_parser(clap::value_parser!(u64))
                        .help("Number of table chains")
                )
                .arg(
                    Arg::new("chain length")
                        .long("chain-len")
                        .default_value(DEFAULT_CHAIN_LENGTH)
                        .value_parser(clap::value_parser!(u64))
                        .help("Length of table chains")
                )
                .subcommand(
                    Command::new(HELLMAN_GENERATE)
                        .about("Generate preprocessing tables")
                        .arg(
                            Arg::new("table number")
                                .long("tables")
                                .default_value(DEFAULT_GENERATED_TABLE_NUMBER)
                                .value_parser(clap::value_parser!(usize))
                                .help("Number of tables to generate")
                        )
                )
                .subcommand(
                    Command::new(HELLMAN_CONVERT)
                        .about("Convert preprocessing tables into \
                            different format")
                        .arg(
                            Arg::new("output format")
                                .long("out-format")
                                .default_value("json")
                                .value_parser(["json", "bin"])
                                .help("Format of output table file")
                        )
                        // TODO allow using arrays and ranges
                        .arg(
                            Arg::new("table index")
                                .short('i')
                                .long("index")
                                .value_parser(clap::value_parser!(usize))
                                .help("Index of table to convert \
                                    (number after \'_\' in file name)")
                        )
                        .arg(
                            Arg::new("overwrite table")
                                .short('f')
                                .long("force")
                                .action(ArgAction::SetTrue)
                                .help("Overwrite existing tables")
                        )
                )
                .subcommand(
                    Command::new(HELLMAN_EXECUTE)
                        .about("Execute Hellman's attack")
                        .arg(
                            Arg::new("table number")
                                .long("tables")
                                .default_value(DEFAULT_TABLE_NUMBER)
                                .value_parser(clap::value_parser!(usize))
                                .help("Number of tables to process")
                        )
                        .arg(
                            Arg::new("table in process memory number")
                                .long("mem-tables")
                                .default_value(DEFAULT_PROC_MEMORY_TABLE_NUMBER)
                                .value_parser(clap::value_parser!(usize))
                                .help("Number of tables in process memory")
                        )
                )
        )
        .get_matches();

    // TODO improve error handling of parsing.
    let message = matches
        .get_one::<String>("message")
        .unwrap();

    let message_transform = match matches
        .get_one::<String>("message transform")
        .unwrap()
        .as_str()
    {
        TRANSFORM_RANDOM_NUMBER => 
            MessageTransform::AppendRandomNumber,
        TRANSFORM_NUMBER_IN_SEQUENCE => 
            MessageTransform::AppendNumberInSequence(1),
        TRANSFORM_MUTATE
            => MessageTransform::Mutate,
        _ => {
            eprintln!("Invalid message transform");
            process::exit(-1);
        }
    };

    let hash_size = matches
        .get_one::<usize>("hash size")
        .unwrap();
    
    let success_probability = matches
        .get_one::<f32>("success probability")
        .unwrap();
    
    let verbose_tries = matches
        .get_one::<u64>("verbose tries")
        .unwrap();

    let initial_state = AttackState::new(
        message,
        message_transform,
    );

    let subcommand = matches.subcommand();

    if let Some((ATTACK_BIRTHDAYS, _)) = subcommand {
        let _ = birthdays::Birthdays::build(
            initial_state,
            *hash_size,
            *success_probability,
            *verbose_tries
        )
            .expect("Failed to initialize struct")
            .execute();
    }
    else if let Some((ATTACK_BRUTEFORCE, _)) = subcommand {
        let _ = bruteforce::BruteForce::build(
            initial_state,
            *hash_size,
            *success_probability,
            *verbose_tries
        )
            .expect("Failed to initialize struct")
            .execute();
    }
    else if let Some((ATTACK_HELLMAN, hellman_matches)) = subcommand {
        let directory_path = hellman_matches
            .get_one::<String>("table directory")
            .unwrap();
        let file_format = hellman_matches
            .get_one::<String>("table file format")
            .unwrap();
        let reduction_output_size = hellman_matches
            .get_one::<usize>("reduction output size")
            .unwrap();
        let chain_number = hellman_matches
            .get_one::<u64>("chain number")
            .unwrap();
        let chain_length = hellman_matches
            .get_one::<u64>("chain length")
            .unwrap();

        let hellman_subcommand = hellman_matches.subcommand();
        
        if let Some((HELLMAN_GENERATE, gen_matches)) = hellman_subcommand {        
            let table_number = gen_matches
                .get_one::<usize>("table number")
                .unwrap();

            let _ = hellman::Hellman::build(
                initial_state,
                *hash_size,
                *reduction_output_size,
                (*table_number).into(),
                *chain_number,
                *chain_length,
                directory_path,
                file_format
            )
                .expect("Failed to initialize struct")
                .generate();
        }
        else if let Some((HELLMAN_CONVERT, con_matches)) = hellman_subcommand {        
            let output_format = con_matches
                .get_one::<String>("output format")
                .unwrap();
            let table_index = con_matches
                .get_one::<usize>("table index")
                .unwrap();
            let force = con_matches
                .get_flag("overwrite table");

            let _ = hellman::Hellman::build(
                initial_state,
                *hash_size,
                *reduction_output_size,
                1.into(),
                *chain_number,
                *chain_length,
                directory_path,
                file_format
            )
                .expect("Failed to initialize struct")
                .convert(output_format, *table_index, force);
        }
        else if let Some((HELLMAN_EXECUTE, exec_matches)) = hellman_subcommand {
            let table_number = exec_matches
                .get_one::<usize>("table number")
                .unwrap();
            let mem_table_number = exec_matches
                .get_one::<usize>("table in process memory number")
                .unwrap();

            let _ = hellman::Hellman::build(
                initial_state,
                *hash_size,
                *reduction_output_size,
                (*table_number, *mem_table_number).into(),
                *chain_number,
                *chain_length,
                directory_path,
                file_format
            )
                .expect("Failed to initiate the attack")
                .execute();
        }
        else {
            eprintln!("Invalid attack type");
            process::exit(-1);
        }
    }
    else {
        eprintln!("Invalid attack type");
        process::exit(-1);
    }
}
