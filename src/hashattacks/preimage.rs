use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::constants::*;
use super::{AttackConfig, MessageHash};


fn min_probability_from_tries(tries: u64) -> f32 {
    1.0 + (-(tries as f32) / PREIMAGE_HASH_COUNT as f32).exp()
}

fn tries_from_probability(probability: f32) -> u64 {
    (PREIMAGE_HASH_COUNT as f32 * (1.0 / (1.0 - probability)).ln()).ceil() 
        as u64
}

fn compare_hashes(message_hash1: &MessageHash, message_hash2: &MessageHash,
    prefix_len_in_bits: usize) -> bool {
    let prefix_len_in_bytes = prefix_len_in_bits / 8;
    let prefix_index = message_hash1.hash.len() - prefix_len_in_bytes;

    message_hash1.hash[prefix_index..] == message_hash2.hash[prefix_index..] 
}

pub fn attack(mut config: AttackConfig, running: Arc<AtomicBool>)
    -> Option<String> {
    let original_message_hash = config.get_message_hash();

    println!("Initialising preimage search attack...\n{}\n",
        original_message_hash
    );

    println!("Searching for a preimage...");
    
    let mut i: u64 = 1;

    while i <= NUMBER_OF_VERBOSE_TRIES && running.load(Ordering::SeqCst) {
        let message_hash = config.generate_message();
        
        println!("{}\t{}", i, message_hash);

        if compare_hashes(
            &original_message_hash,
            &message_hash,
            PREIMAGE_PREFIX_LEN
        ) {
            println!("[SUCCESS] Found preimage on iteration {}!\n{}\n{}\n",
                i, original_message_hash, message_hash
            );

            return Some(message_hash.message);
        }

        i += 1;
    }

    println!("...\n");

    let tries_num = tries_from_probability(PROBABILITY);

    while i <= tries_num && running.load(Ordering::SeqCst) {
        let message_hash = config.generate_message();
        
        if compare_hashes(
            &original_message_hash,
            &message_hash,
            PREIMAGE_PREFIX_LEN
        ) {
            println!("[SUCCESS] Found preimage on iteration {}!\n{}\n{}\n",
                i, original_message_hash, message_hash
            );

            return Some(message_hash.message);
        }

        i += 1;
    }

    println!("[FAILURE] Preimage was not found in {} iterations\n", i);

    None
}
