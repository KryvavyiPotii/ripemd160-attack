use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use super::{AttackResult, AttackState, HashAttack, MessageHash};


const NUMBER_OF_VERBOSE_TRIES: u64 = 30;
const PROBABILITY: f32 = 0.95;
const TRUNCATED_HASH_SIZE_IN_BITS: usize = 32;
const TRUNCATED_HASH_SIZE_IN_BYTES: usize = TRUNCATED_HASH_SIZE_IN_BITS / 8;
const HASH_COUNT: u64 = 1 << TRUNCATED_HASH_SIZE_IN_BITS;


fn min_probability_from_tries(tries: u64) -> f32 {
    1.0 + (-(tries as f32) / HASH_COUNT as f32).exp()
}

fn tries_from_probability(probability: f32) -> u64 {
    (HASH_COUNT as f32 * (1.0 / (1.0 - probability)).ln()).ceil()
        as u64
}

fn find_collision(
    hashes: &mut Vec<MessageHash>,
    prefix_len_in_bytes: usize
) -> Option<(MessageHash, MessageHash)> {
    let i = hashes.len();

    if i <= 1 {
        return None;
    }

    let messagehash1 = hashes.pop().unwrap();
    let hash_len = messagehash1.hash_len();

    let prefix_index = if hash_len >= prefix_len_in_bytes {
        hash_len - prefix_len_in_bytes
    }
    else {
        0
    };

    for (j, messagehash2) in hashes.iter().enumerate() {
        let message1 = &messagehash1.message();
        let hash1 = &messagehash1.hash_value()[prefix_index..];
        let message2 = &messagehash2.message();
        let hash2 = &messagehash2.hash_value()[prefix_index..]; 

        if message1 != message2 && hash1 == hash2 {
            println!(
                "[SUCCESS] Found collision in iteration {}-{}!\n{}\n{}\n",
                i,
                j,
                messagehash1,
                messagehash2
            );

            return Some((messagehash1, messagehash2.clone()));
        }
    }

    hashes.push(messagehash1);

    None
}


pub struct Birthdays {
    state: AttackState,
}

impl Birthdays {
    pub fn new(initial_state: AttackState) -> Self {
        Self { state: initial_state }
    }
}

impl HashAttack for Birthdays {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        println!("Initialising birthday attack...\n{}\n",
            self.state.messagehash()
        );

        println!("Searching for a collision...");
        
        let mut i = 1;
        let mut calculated_hashes = Vec::new();

        while i <= NUMBER_OF_VERBOSE_TRIES && running.load(Ordering::SeqCst) {
            let messagehash = self.state.update();
            
            println!("{}\t{}", i, messagehash);        
            
            calculated_hashes.push(messagehash);
            
            if let Some((mh1, mh2)) = find_collision(
                &mut calculated_hashes,
                TRUNCATED_HASH_SIZE_IN_BITS
            ) {
                return AttackResult::Collision(mh1.message(), mh2.message());
            }
            
            i += 1;
        }

        println!("...\n");

        let tries_num = tries_from_probability(PROBABILITY);
        
        while i <= tries_num && running.load(Ordering::SeqCst) {
            let messagehash = self.state.update();

            calculated_hashes.push(messagehash);
            
            if let Some((mh1, mh2)) = find_collision(
                &mut calculated_hashes,
                TRUNCATED_HASH_SIZE_IN_BITS
            ) {
                return AttackResult::Collision(mh1.message(), mh2.message());
            }

            i += 1;
        }
        
        println!("[FAILURE] Collision was not found in {} iterations\n", i);

        AttackResult::Failure
    }
}
