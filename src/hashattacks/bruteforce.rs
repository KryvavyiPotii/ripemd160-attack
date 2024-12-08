use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use super::{AttackResult, AttackState, HashAttack};
use crate::messagehash::HashValue;


const NUMBER_OF_VERBOSE_TRIES: u64 = 30;
const PROBABILITY: f32 = 0.95;
const TRUNCATED_HASH_SIZE_IN_BITS: usize = 16;
const TRUNCATED_HASH_SIZE_IN_BYTES: usize = TRUNCATED_HASH_SIZE_IN_BITS / 8;
const HASH_COUNT: u64 = 1 << TRUNCATED_HASH_SIZE_IN_BITS;


fn min_probability_from_tries(tries: u64) -> f32 {
    1.0 + (-(tries as f32) / HASH_COUNT as f32).exp()
}

fn tries_from_probability(probability: f32) -> u64 {
    (HASH_COUNT as f32 * (1.0 / (1.0 - probability)).ln())
        .ceil() as u64
}

fn equal_hashes(
    hash1: &HashValue,
    hash2: &HashValue,
    prefix_len_in_bytes: usize
) -> bool {
    if hash1.len() != hash2.len() {
        return false;
    }

    let hash_len = hash1.len();

    let prefix_index = if hash_len >= prefix_len_in_bytes {
        hash_len - prefix_len_in_bytes
    }
    else {
        0
    };

    hash1[prefix_index..] == hash2[prefix_index..] 
}


pub struct BruteForce {
    state: AttackState,
}

impl BruteForce {
    pub fn new(initial_state: AttackState) -> Self  {
        Self { state: initial_state }
    }
}

impl HashAttack for BruteForce {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        let original_messagehash = self.state.messagehash();

        println!(
            "Initialising preimage search attack...\n{}\n",
            original_messagehash
        );
        println!("Searching a preimage...");
        
        let mut i = 1;

        while i <= NUMBER_OF_VERBOSE_TRIES && running.load(Ordering::SeqCst) {
            let messagehash = self.state.update();
            
            println!("{}\t{}", i, messagehash);

            if equal_hashes(
                original_messagehash.hash_value(),
                messagehash.hash_value(),
                TRUNCATED_HASH_SIZE_IN_BYTES
            ) {
                println!(
                    "[SUCCESS] Found preimage on iteration {}!\n{}\n{}\n",
                    i,
                    original_messagehash,
                    messagehash
                );

                return AttackResult::Preimage(messagehash.message());
            }

            i += 1;
        }

        println!("...\n");

        let tries_num = tries_from_probability(PROBABILITY);

        while i <= tries_num && running.load(Ordering::SeqCst) {
            let messagehash = self.state.update();
            
            if equal_hashes(
                original_messagehash.hash_value(),
                messagehash.hash_value(),
                TRUNCATED_HASH_SIZE_IN_BYTES
            ) {
                println!(
                    "[SUCCESS] Found preimage on iteration {}!\n{}\n{}\n",
                    i,
                    original_messagehash,
                    messagehash
                );

                return AttackResult::Preimage(messagehash.message());
            }

            i += 1;
        }

        println!("[FAILURE] Preimage was not found in {} iterations\n", i);

        AttackResult::Failure
    }
}
