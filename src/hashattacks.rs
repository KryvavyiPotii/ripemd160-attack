use std::{
    fmt,
    sync::{Arc, atomic::{AtomicBool, Ordering}}
};

use chrono::prelude::*;
use ripemd::{Digest, Ripemd160};

use crate::messagehash::{HashValue, MessageHash};

use messagetransform::MessageTransform;


pub mod birthdays;
pub mod bruteforce;
pub mod hellman;
pub mod messagetransform;


enum AttackIteration {
    Preimage(u64),
    Birthdays(u64, u64),
}

impl From<u64> for AttackIteration {
    fn from(iteration: u64) -> Self {
        Self::Preimage(iteration)
    }
}

impl From<usize> for AttackIteration {
    fn from(iteration: usize) -> Self {
        Self::Preimage(iteration as u64)
    }
}

impl From<(u64, u64)> for AttackIteration {
    fn from(birthdays_iteration: (u64, u64)) -> Self {
        let (i, j) = birthdays_iteration;

        Self::Birthdays(i, j)
    }
}

impl fmt::Display for AttackIteration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preimage(i) => write!(f, "{}", i),
            Self::Birthdays(i, j) => write!(f, "{}-{}", i, j)
        }
    }
}


enum AttackLog<'a> {
    Info(&'a str),
    Init(&'a MessageHash),
    TableGenInit(usize),
    TableGenSuccess(&'a str),
    Term(&'a str, AttackIteration),
    Result(&'a AttackResult, AttackIteration),
    PerTableResult(&'a AttackResult, &'a str, AttackIteration)
}

impl<'a> AttackLog<'a> {
    fn log(&self) {
        let utc: DateTime<Utc> = Utc::now();

        match self {
            Self::Info(info) => println!("{} INFO, {}", utc, info),
            Self::Init(messagehash) =>
                println!(
                    "{} INIT, Message: \"{}\", Hash: {}",
                    utc,
                    messagehash.message(),
                    messagehash.hash_value()
                ),
            Self::TableGenInit(tables_number) =>
                println!("{} INIT, Table number: {}",
                    Utc::now(),
                    tables_number
                ),
            Self::TableGenSuccess(table_path) =>
                println!("{} SUCCESS, Filepath: {}",
                    Utc::now(),
                    table_path
                ),
            Self::Term(origin, iteration) =>
                println!(
                    "{} TERM, Origin: {}, Iteration: {}",
                    utc,
                    origin,
                    iteration
                ),
            Self::Result(result, iteration) => match result {
                AttackResult::Failure => println!(
                        "{} FAILURE, Iteration: {}",
                        utc,
                        iteration
                    ),
                AttackResult::Preimage(preimage) => println!(
                        "{} SUCCESS, Iteration: {}, \
                        Preimage: \"{}\", Preimage hash: {}",
                        utc,
                        iteration,
                        preimage.message(),
                        preimage.hash_value()
                    ),
                AttackResult::Collision(messagehash1, messagehash2) => println!(
                        "{} SUCCESS, Iteration: {}, \
                        Message1: \"{}\", Hash1: {}, \
                        Message2: \"{}\", Hash2: {}",
                        utc,
                        iteration,
                        messagehash1.message(),
                        messagehash2.hash_value(),
                        messagehash2.message(),
                        messagehash2.hash_value()
                    )
            },
            Self::PerTableResult(result, filepath, iteration) => match result {
                AttackResult::Failure => println!(
                        "{} FAILURE, Table: {}, Iteration: {}",
                        utc,
                        filepath,
                        iteration
                    ),
                AttackResult::Preimage(preimage) => println!(
                        "{} SUCCESS, Table: {}, Iteration: {}, \
                        Preimage: \"{}\", Preimage hash: {}",
                        utc,
                        filepath,
                        iteration,
                        preimage.message(),
                        preimage.hash_value()
                    ),
                _ => ()
            },
        }
    }
}


pub trait HashAttack {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult;
    
    fn execute(&mut self) -> AttackResult {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc_async::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");

        let result = self.attack(running);

        result
    }
}

#[derive(Clone, Debug)]
pub enum AttackResult {
    Preimage(MessageHash),
    Collision(MessageHash, MessageHash),
    Failure,
}

#[derive(Clone, Debug)]
pub struct AttackState {
    hasher: Ripemd160,
    message: String,
    message_transform: MessageTransform,
}

impl AttackState {
    pub fn new(
        message: &str,
        message_transform: MessageTransform
    ) -> Self {
        let hasher = Ripemd160::new();

        Self {
            hasher,
            message: message.to_string(),
            message_transform,
        }
    }

    pub fn messagehash(&mut self) -> MessageHash {
        self.hasher.update(&self.message);

        MessageHash::new(
            &self.message,
            HashValue::new(self.hasher.finalize_reset())
        ) 
    }

    pub fn hash_message(&mut self, message: &[u8]) -> HashValue {
        self.hasher.update(&message);

        HashValue::new(self.hasher.finalize_reset())
    }

    pub fn update(&mut self) -> MessageHash {
        let modified_message = self.message_transform.transform(&self.message);
       
        self.hasher.update(&modified_message);

        let modified_hash = HashValue::new(self.hasher.finalize_reset());

        MessageHash::new(&modified_message, modified_hash)
    }
}
