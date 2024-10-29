use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::constants::*;
use super::{AttackConfig, MessageHash};


fn min_probability_from_tries(tries: u64) -> f32 {
    1.0 + (-(tries as f32) / BIRTHDAYS_HASH_COUNT as f32).exp()
}

fn tries_from_probability(probability: f32) -> u64 {
    (BIRTHDAYS_HASH_COUNT as f32 * (1.0 / (1.0 - probability)).ln()).ceil()
        as u64
}

fn find_collision(hashes: &mut Vec<MessageHash>, prefix_len_in_bits: usize)
    -> Option<(MessageHash, MessageHash)> {
    let i = hashes.len();

    if i <= 1 {
        return None;
    }

    let message_hash1 = hashes.pop().unwrap();

    let prefix_len_in_bytes = prefix_len_in_bits / 8;
    let prefix_index = message_hash1.hash.len() - prefix_len_in_bytes;

    for (j, message_hash2) in hashes.iter().enumerate() {
        let message1 = &message_hash1.message;
        let hash1 = &message_hash1.hash[prefix_index..];
        let message2 = &message_hash2.message;
        let hash2 = &message_hash2.hash[prefix_index..]; 

        if message1 != message2 && hash1 == hash2 {
            println!("[SUCCESS] Found collision in iteration {}-{}!\n{}\n{}\n",
                i, j, message_hash1, message_hash2
            );

            return Some((message_hash1, message_hash2.clone()));
        }
    }

    hashes.push(message_hash1);

    None
}

pub fn attack(mut config: AttackConfig, running: Arc<AtomicBool>)
    -> Option<(String, String)> {
    println!("Initialising birthday attack...\n{}\n",
        config.get_message_hash()
    );

    println!("Searching for a collision...");
    
    let mut i: u64 = 1;
    let mut calculated_hashes: Vec<MessageHash> = Vec::new();

    while i <= NUMBER_OF_VERBOSE_TRIES && running.load(Ordering::SeqCst) {
        let message_hash = config.generate_message();
        
        println!("{}\t{}", i, message_hash);        
        
        calculated_hashes.push(message_hash);
        
        if let Some((mh1, mh2)) = find_collision(
            &mut calculated_hashes,
            BIRTHDAYS_PREFIX_LEN
        ) {
            return Some((mh1.message, mh2.message));
        }
        
        i += 1;
    }

    println!("...\n");

    let tries_num = tries_from_probability(PROBABILITY);
    
    while i <= tries_num && running.load(Ordering::SeqCst) {
        let message_hash = config.generate_message();

        calculated_hashes.push(message_hash);
        
        if let Some((mh1, mh2)) = find_collision(
            &mut calculated_hashes,
            BIRTHDAYS_PREFIX_LEN
        ) {
            return Some((mh1.message, mh2.message));
        }

        i += 1;
    }
    
    println!("[FAILURE] Collision was not found in {} iterations\n", i);

    None
}
