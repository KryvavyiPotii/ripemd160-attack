use std::process;

use clap::{Command, Arg};

use hashattacks::{*, messagetransform::*};

mod hashattacks;
mod messagehash;


const DEFAULT_MESSAGE: &str = "Some huge message";
const DEFAULT_HELLMAN_TABLE_NUMBER: u32 = 1;
const DEFAULT_HELLMAN_VARIABLE_NUMBER: u32 = 1 << 14;
const DEFAULT_HELLMAN_ITERATION_COUNT: u32 = 1 << 7;


fn main() {
    let matches = Command::new("ripemd160-attack")
        .version("0.1.0")
        .about("Executes various attacks on RIPEMD160 hash.")
        .arg(
            Arg::new("message")
                .short('m')
                .long("message")
                .help("Initial message to process")
        )
        .arg(
            Arg::new("attack type")
                .short('a')
                .long("attack-type")
                .help("preimage, birthdays or hellman")
        )
        .arg(
            Arg::new("message transform")
                .short('t')
                .long("message-transform")
                .help("random_number, number_in_sequence or mutate")
        )
        .arg(
            Arg::new("hellman table number")
                .long("tables")
                .help("Number of tables for the Hellman attack")
                .value_parser(clap::value_parser!(u32))
        )
        .arg(
            Arg::new("hellman table variable number")
                .long("vars")
                .help("Number of table variables for the Hellman attack")
                .value_parser(clap::value_parser!(u32))
        )
        .arg(
            Arg::new("hellman table iteration count")
                .long("iters")
                .help("Number of table iterations for the Hellman attack")
                .value_parser(clap::value_parser!(u32))
        )
        .get_matches();

    let message = match matches.get_one::<String>("message") {
        Some(message) => message,
        None => DEFAULT_MESSAGE
    };

    let message_transform = match matches
        .get_one::<String>("message transform")
    {
        Some(transform) => match transform.as_str() {
            "random_number" => MessageTransform::AppendRandomNumber,
            "number_in_sequence" => MessageTransform::AppendNumberInSequence(1),
            "mutate" => MessageTransform::Mutate,
            _ => {
                println!("Invalid message transform.");
                process::exit(-1);
            }
        }
        None => MessageTransform::AppendRandomNumber
    };

    let initial_state = AttackState::new(
        message,
        message_transform,
    );

    match matches
        .get_one::<String>("attack type")
        .unwrap_or_else(|| {
            println!("Attack type not specified.");
            process::exit(-1);
        })
        .as_str()
    {
        "birthdays" => birthdays::Birthdays::new(initial_state).execute(),
        "preimage" => bruteforce::BruteForce::new(initial_state).execute(),
        "hellman" => {
                let table_number = matches
                    .get_one::<u32>("hellman table number")
                    .unwrap_or(&DEFAULT_HELLMAN_TABLE_NUMBER);
                let variable_number = matches
                    .get_one::<u32>("hellman table variable number")
                    .unwrap_or(&DEFAULT_HELLMAN_VARIABLE_NUMBER);
                let iteration_count = matches
                    .get_one::<u32>("hellman table iteration count")
                    .unwrap_or(&DEFAULT_HELLMAN_ITERATION_COUNT);
         
                hellman::Hellman::new(
                    initial_state,
                    *table_number,
                    *variable_number,
                    *iteration_count
                ).execute()
            },
        _ => {
            println!("Invalid attack type.");
            process::exit(-1);
        }
    }; 
}
