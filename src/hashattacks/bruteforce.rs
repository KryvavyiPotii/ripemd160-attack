use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use crate::messagehash::HashValue;

use super::{AttackLog, AttackResult, AttackState, HashAttack};


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

    /*
    fn min_probability_from_tries(&self, tries: u64) -> f32 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count = 1 << hash_size_in_bits;

        1.0 + (-(tries as f32) / hash_count as f32).exp()
    }
    */

    fn tries_from_probability(&self) -> u64 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count: u64 = 1 << hash_size_in_bits;
        let probability = self.success_probability;
        
        hash_count * (1.0 / (1.0 - probability)).ln().ceil() as u64
    }
}

impl HashAttack for BruteForce {
    fn attack(
        &mut self,
        running: Arc<AtomicBool>
    ) -> Result<AttackResult, &'static str> {
        let original_messagehash = self.state.messagehash();

        AttackLog::Init(&original_messagehash).log();
        
        let mut i: u64 = 1; 

        while i <= self.verbose_tries_number {
            if !running.load(Ordering::SeqCst) {
                AttackLog::Term("BruteForce.attack", i.into()).log();
                return Err("Attack terminated");
            }
            
            let messagehash = self.state.update();
            
            AttackLog::Info(&format!("{}\t{}", i, messagehash)).log();        

            if original_messagehash.hash_value().equal_to(
                messagehash.hash_value(),
                self.hash_size_in_bytes
            ) {
                let result = AttackResult::Preimage(messagehash);

                AttackLog::Success(&result, i.into()).log();

                return Ok(result);
            }

            i += 1;
        }

        let tries_num = self.tries_from_probability();

        while i <= tries_num {
            if !running.load(Ordering::SeqCst) {
                AttackLog::Term("BruteForce.attack", i.into()).log();
                return Err("Attack terminated");
            }
            
            let messagehash = self.state.update();
            
            if original_messagehash.hash_value().equal_to(
                messagehash.hash_value(),
                self.hash_size_in_bytes
            ) {
                let result = AttackResult::Preimage(messagehash);

                AttackLog::Success(&result, i.into()).log();

                return Ok(result);
            }

            i += 1;
        }

        AttackLog::Failure(i.into()).log();
        
        Err("Attack failed")
    }
}
