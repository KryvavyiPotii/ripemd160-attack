use rand::seq::SliceRandom;
use ripemd::{Digest, Ripemd160, Ripemd160Core, digest::OutputSizeUser};
use generic_array::GenericArray;
use rand::{thread_rng, Rng};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{time, fmt};
use crate::constants::*;

pub mod constants;
pub mod preimage;
pub mod birthdays;

const MESSAGE1: &str = "Some huge message";
const MESSAGE2: &str = "Another big message";


pub fn attack(config: AttackConfig) -> AttackResult {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc_async::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let now = time::Instant::now();
    
    let result = match config.attack_type {
        AttackType::FindPreimage => 
            match preimage::attack(config, running) {
                Some(preimage) => AttackResult::Preimage(preimage),
                None => AttackResult::Failure,
            }
        AttackType::Birthdays => 
            match birthdays::attack(config, running) {
                Some(collision) => AttackResult::Collision(collision),
                None => AttackResult::Failure,
            }
    };

    let elapsed_time = now.elapsed();

    println!("[TIME] Attack took {:.2?}", elapsed_time);

    result
}

fn append_number_to_message(message: &str, num: u64) -> String {
    format!("{message}{num}")
}

fn append_random_number_to_message(message: &str) -> String { 
    let rand_num: u64 = thread_rng().gen_range(1..BIRTHDAYS_HASH_COUNT);

    format!("{message}{rand_num}")
}

fn switch_case(character: char) -> String {
    if character.is_uppercase() {
        character.to_lowercase().to_string()
    } else {
        character.to_uppercase().to_string()
    }
}

fn generate_random_ascii() -> String {
    thread_rng().gen_range(' '..='~').to_string()
}

fn mutate(character: char) -> String {
    let default = "*";
    let mut rng = thread_rng();

    let similar_chars = vec![
        vec!['a', 'A', '@', '4'],
        vec!['b', '6'],
        vec!['B', '%', '&', '8'],
        vec!['c', 'C', '(', '[', '{'],
        vec!['D', 'o', 'O', '0'],
        vec!['e', 'E', '3'],
        vec!['f', '+'],
        vec!['g', 'q', '9', '?'],
        vec!['i', 'I', 'l', 'L', '|', '!', '1'],
        vec!['s', 'S', '$', '5'],
        vec!['t', 'T', '7'],
        vec!['u', 'U', 'v', 'V'],
        vec!['z', 'Z', '2'],
        vec!['-', '=', '~'],
        vec!['\t', ' ', '_']
    ];

    for similar in similar_chars.iter() {
        if similar.contains(&character) {
            let mutation: Vec<&char> = similar.iter()
                .filter(|&c| *c != character)
                .collect();

            mutation.choose(&mut rng).unwrap().to_string();
        }
    }

    default.to_string()
}

fn transform_message_randomly(message: &str) -> String {
    let mut rng = thread_rng();

    message.chars()
        .map(|c| {
            let transform_type: u32 = rng.gen_range(0..=3);

            match transform_type {
                0 => switch_case(c),
                1 => generate_random_ascii(),
                2 => mutate(c),
                _ => c.to_string(),
            }
        })
        .collect()
}


#[derive(Clone, Debug)]
pub struct MessageHash {
    pub message: String,
    pub hash: GenericArray<u8, <Ripemd160Core as OutputSizeUser>::OutputSize>,
}

impl MessageHash {
    pub fn new(hasher: &mut Ripemd160, message: String) -> Self {
        hasher.update(&message);

        MessageHash {
            message,
            hash: hasher.finalize_reset(),
        }
    }
}

impl fmt::Display for MessageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{:x}", self.message, self.hash)
    }
}


pub enum AttackResult {
    Preimage(String),
    Collision((String, String)),
    Failure,
}

pub enum AttackType {
    FindPreimage,                                                                                                                                 
    Birthdays,                                                                                                                                    
}                                                                                                                                                 
                                                                                                                                                  
impl AttackType {                                                                                                                                 
    pub fn build(attack_type: &str) -> Result<Self, &'static str> {
        match attack_type {
            "preimage" => Ok(Self::FindPreimage),
            "birthdays" => Ok(Self::Birthdays),
            _ => return Err("Incorrect attack type"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum MessageModificationVariant {
    AppendRandomNumber,
    Transform,
    AppendNumberInSequence(u64),
}

impl MessageModificationVariant{
    pub fn build(attack_type: &str) -> Result<Self, &'static str> {
        match attack_type {
            "random_number" | "1" => Ok(Self::AppendRandomNumber),
            "transform" | "2" => Ok(Self::Transform),
            "number_in_sequence" | "3" => Ok(Self::AppendNumberInSequence(1)),
            _ => return Err("Incorrect message modification variant"),
        }
    }
}

pub struct AttackConfig {
    attack_type: AttackType,
    pub hasher: Ripemd160,
    pub message: String,
    pub hash: GenericArray<u8, <Ripemd160Core as OutputSizeUser>::OutputSize>,
    message_modification_variant: MessageModificationVariant,
}

impl AttackConfig {
   pub fn build(mut args: impl Iterator<Item = String>)
        -> Result<Self, &'static str> {
        let mut hasher = Ripemd160::new();

        // Skip executable path.
        args.next();

        let attack_type = match args.next() {
            Some(arg) => AttackType::build(&arg)?,
            None => return Err("Failed to get attack type"),
        };

        let message_modification_variant = match args.next() {
            Some(arg) => MessageModificationVariant::build(&arg)?,
            None => return Err("Failed to get message modification variant"),
        };
            
        let message = match attack_type {
            AttackType::FindPreimage => MESSAGE1.to_string(),
            AttackType::Birthdays => MESSAGE2.to_string(),
        };
        hasher.update(&message);
        let hash = hasher.finalize_reset();

        Ok(Self {
            attack_type,
            hasher,
            message,
            hash,
            message_modification_variant,
        })
    }

    pub fn get_message_hash(&self) -> MessageHash {
        MessageHash {
            message: self.message.clone(),
            hash: self.hash,
        }
    }

    pub fn generate_message(&mut self) -> MessageHash {
        let modified_message = match self.message_modification_variant {
            MessageModificationVariant::AppendRandomNumber =>
                append_random_number_to_message(&self.message),
            MessageModificationVariant::Transform =>
                transform_message_randomly(&self.message),
            MessageModificationVariant::AppendNumberInSequence(num) => {
                self.message_modification_variant = 
                    MessageModificationVariant::AppendNumberInSequence(num + 1);
                append_number_to_message(&self.message, num)
            }
        };
       
        self.hasher.update(&modified_message);

        let modified_hash = self.hasher.finalize_reset();

        MessageHash {
            message: modified_message,
            hash: modified_hash,
        }
    }
}
