use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use crate::messagehash::HashValue;

use super::{AttackResult, AttackState, HashAttack};


pub struct BruteForce {
    state: AttackState,
    hash_size_in_bytes: usize,
    success_probability: f32,
    verbose_tries_number: u64
}

impl BruteForce {
    pub fn build(
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        success_probability: f32,
        verbose_tries_number: u64
    ) -> Result<Self, &'static str> {
        if hash_size_in_bytes > HashValue::len() {
            return Err("Invalid hash size");
        }

        Ok(
            Self { 
                state: initial_state,
                hash_size_in_bytes,
                success_probability,
                verbose_tries_number
            }
        )
    }

    fn min_probability_from_tries(&self, tries: u64) -> f32 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count = 1 << hash_size_in_bits;

        1.0 + (-(tries as f32) / hash_count as f32).exp()
    }

    fn tries_from_probability(&self) -> u64 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count: u64 = 1 << hash_size_in_bits;
        let probability = self.success_probability;
        
        hash_count * (1.0 / (1.0 - probability)).ln().ceil() as u64
    }
}

impl HashAttack for BruteForce {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        let original_messagehash = self.state.messagehash();

        println!(
            "[INFO] Initialising brute-force attack...\n{}\n",
            original_messagehash
        );
        println!("[INFO] Searching for a preimage...");
        
        let mut i: u64 = 1;

        while i <= self.verbose_tries_number && running.load(Ordering::SeqCst) {
            let messagehash = self.state.update();
            
            println!("{}\t{}", i, messagehash);

            if original_messagehash.hash_value().equal_to(
                messagehash.hash_value(),
                self.hash_size_in_bytes
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

        let tries_num = self.tries_from_probability();

        while i <= tries_num && running.load(Ordering::SeqCst) {
            let messagehash = self.state.update();
            
            if original_messagehash.hash_value().equal_to(
                messagehash.hash_value(),
                self.hash_size_in_bytes
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
