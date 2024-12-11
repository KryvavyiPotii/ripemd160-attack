use std::process;

use clap::{Command, Arg};

use hashattacks::{*, messagetransform::*};

mod hashattacks;
mod messagehash;


const DEFAULT_MESSAGE: &str = "Some huge message";
const DEFAULT_VERBOSE_TRIES_NUMBER: u64 = 30;
const DEFAULT_SUCCESS_PROBABILITY: f32 = 0.95;

const DEFAULT_HASH_SIZE_IN_BYTES: usize = 2;

const DEFAULT_HELLMAN_REDUNDANCY_OUTPUT_SIZE_IN_BYTES: usize = 16;
const DEFAULT_HELLMAN_TABLE_NUMBER: usize = 1;
const DEFAULT_HELLMAN_STORED_TABLE_NUMBER: usize = 0;
const DEFAULT_HELLMAN_VARIABLE_NUMBER: u32 = 1 << 14;
const DEFAULT_HELLMAN_ITERATION_COUNT: u32 = 1 << 7;

const ATTACK_BRUTEFORCE: &str = "bruteforce";
const ATTACK_BIRTHDAYS: &str  = "birthdays";
const ATTACK_HELLMAN: &str    = "hellman";

const TRANSFORM_RANDOM_NUMBER: &str      = "random_number";
const TRANSFORM_NUMBER_IN_SEQUENCE: &str = "number_in_sequence";
const TRANSFORM_MUTATE: &str             = "mutate";


fn main() {
    let matches = Command::new("ripemd160-attack")
        .version("0.4.0")
        .about("Executes various attacks on RIPEMD160 hash.")
        .arg(
            Arg::new("message")
                .short('m')
                .long("message")
                .default_value(DEFAULT_MESSAGE)
                .help("Initial message to process.")
        )
        .arg(
            Arg::new("message transform")
                .short('t')
                .long("message-transform")
                .value_parser([
                    TRANSFORM_RANDOM_NUMBER,
                    TRANSFORM_NUMBER_IN_SEQUENCE,
                    TRANSFORM_MUTATE
                ])
                .default_value("random_number")
                .help("Type of message modification.")
        )
        .arg(
            Arg::new("hash size")
                .short('s')
                .long("hash-size")
                .value_parser(clap::value_parser!(usize))
                .help("Size of the hash suffix in bytes that will be attacked.")
        )
        .arg(
            Arg::new("success probability")
                .short('p')
                .long("probability")
                .value_parser(clap::value_parser!(f32))
                .help("Expected success probability.")
        )
        .arg(
            Arg::new("verbose tries")
                .long("verbose-tries")
                .value_parser(clap::value_parser!(u64))
                .help("Number of tries that will be outputted.")
        )
        .subcommand(
            Command::new(ATTACK_BRUTEFORCE)
                .about("Executes brute-force attack.")
        )
        .subcommand(
            Command::new(ATTACK_BIRTHDAYS)
                .about("Executes birthdays attack.")
        )
        .subcommand(
            Command::new(ATTACK_HELLMAN)
                .about("Executes Hellman's attack.")
                .arg(
                    Arg::new("redundancy output size")
                        .long("rsize")
                        .value_parser(clap::value_parser!(usize))
                        .help("Redundancy function output size in bytes.")
                )
                .arg(
                    Arg::new("hellman table number")
                        .long("tables")
                        .value_parser(clap::value_parser!(usize))
                        .help("Number of tables.")
                )
                .arg(
                    Arg::new("hellman stored table number")
                        .long("stored-tables")
                        .value_parser(clap::value_parser!(usize))
                        .help("Number of tables written to disk.")
                )
                .arg(
                    Arg::new("hellman table variable number")
                        .long("vars")
                        .value_parser(clap::value_parser!(u32))
                        .help("Number of table variables.")
                )
                .arg(
                    Arg::new("hellman table iteration count")
                        .long("iters")
                        .value_parser(clap::value_parser!(u32))
                        .help("Number of table iterations.")
                )
        )
        .get_matches();

    let message = matches.get_one::<String>("message").unwrap();

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
            println!("Invalid message transform.");
            process::exit(-1);
        }
    };

    let hash_size = matches
        .get_one::<usize>("hash size")
        .unwrap_or(&DEFAULT_HASH_SIZE_IN_BYTES);
    
    let success_probability = matches
        .get_one::<f32>("success probability")
        .unwrap_or(&DEFAULT_SUCCESS_PROBABILITY);
    
    let verbose_tries = matches
        .get_one::<u64>("verbose tries")
        .unwrap_or(&DEFAULT_VERBOSE_TRIES_NUMBER);

    let initial_state = AttackState::new(
        message,
        message_transform,
    );

    match matches.subcommand() {
        Some((ATTACK_BIRTHDAYS, _)) => birthdays::Birthdays::build(
                initial_state,
                *hash_size,
                *success_probability,
                *verbose_tries
            )
                .expect("Failed to initiate the attack.")
                .execute(),
        Some((ATTACK_BRUTEFORCE, _)) => bruteforce::BruteForce::build(
                initial_state,
                *hash_size,
                *success_probability,
                *verbose_tries
            )
                .expect("Failed to initiate the attack.")
                .execute(),
        Some((ATTACK_HELLMAN, sub_m)) => {
            let redundancy_output_size = sub_m
                .get_one::<usize>("redundancy output size")
                .unwrap_or(&DEFAULT_HELLMAN_REDUNDANCY_OUTPUT_SIZE_IN_BYTES);
            let table_number = sub_m
                .get_one::<usize>("hellman table number")
                .unwrap_or(&DEFAULT_HELLMAN_TABLE_NUMBER);
            let stored_table_number = sub_m
                .get_one::<usize>("hellman stored table number")
                .unwrap_or(&DEFAULT_HELLMAN_STORED_TABLE_NUMBER);
            let variable_number = sub_m
                .get_one::<u32>("hellman table variable number")
                .unwrap_or(&DEFAULT_HELLMAN_VARIABLE_NUMBER);
            let iteration_count = sub_m
                .get_one::<u32>("hellman table iteration count")
                .unwrap_or(&DEFAULT_HELLMAN_ITERATION_COUNT);
     
            hellman::Hellman::build(
                initial_state,
                *hash_size,
                *redundancy_output_size,
                *table_number,
                *stored_table_number,
                *variable_number,
                *iteration_count
            )
                .expect("Failed to initiate the attack.")
                .execute()
        },
        _ => {
            println!("Invalid attack type.");
            process::exit(-1);
        }
    }; 
}
