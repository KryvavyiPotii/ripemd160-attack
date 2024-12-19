use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use crate::messagehash::HashValue;

use super::{AttackLog, AttackResult, AttackState, HashAttack, MessageHash};


pub struct Birthdays {
    state: AttackState,
    hash_size_in_bytes: usize,
    success_probability: f32,
    verbose_tries_number: u64
}

impl Birthdays {
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

        1.0 + (-(tries.pow(2) as f32) / (2 * hash_count) as f32).exp()
    }
    */

    fn tries_from_probability(&self) -> u64 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count: u64 = 1 << hash_size_in_bits;
        let probability = self.success_probability;

        let count_part = (2.0 * hash_count as f64).sqrt(); 
        let ln_part = ((1.0 / (1.0 - probability)).ln() as f64).sqrt();
        
        (count_part * ln_part).ceil() as u64
    }

    fn find_collision(
        &self,
        hashes: &mut Vec<MessageHash>
    ) -> Option<(MessageHash, MessageHash, u64, u64)> {
        let i = hashes.len();

        if i <= 1 {
            return None;
        }

        let messagehash1 = hashes.pop().unwrap();
        
        for (j, messagehash2) in hashes.iter().enumerate() {
            if messagehash1.collides_with(
                messagehash2,
                self.hash_size_in_bytes
            ) {
                return Some((
                        messagehash1,
                        messagehash2.clone(),
                        i as u64,
                        j as u64
                    ));
            }
        }

        hashes.push(messagehash1);

        None
    }
}

impl HashAttack for Birthdays {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult {
        AttackLog::Init(&self.state.messagehash()).log();
        
        let mut i = 1;
        let mut calculated_hashes = Vec::new();
        let mut result = AttackResult::Failure;

        while i <= self.verbose_tries_number {
            if !running.load(Ordering::SeqCst) {
                AttackLog::Term("Attack", i.into()).log();
                return AttackResult::Failure;
            }
            
            let messagehash = self.state.update();
            
            println!("{}\t{}", i, messagehash);        
            
            calculated_hashes.push(messagehash);
            
            if let Some((mh1, mh2, i, j)) = self.find_collision(
                &mut calculated_hashes
            ) {
                result = AttackResult::Collision(mh1, mh2); 
                
                AttackLog::Result(&result, (i, j).into()).log();

                return result;
            }
            
            i += 1;
        }

        println!("...\n");

        let tries_num = self.tries_from_probability();
        
        while i <= tries_num {
            if !running.load(Ordering::SeqCst) {
                AttackLog::Term("Attack", i.into()).log();
                return AttackResult::Failure;
            }

            let messagehash = self.state.update();

            calculated_hashes.push(messagehash);
            
            if let Some((mh1, mh2, i, j)) = self.find_collision(
                &mut calculated_hashes
            ) {
                result = AttackResult::Collision(mh1, mh2); 
                
                AttackLog::Result(&result, (i, j).into()).log();

                return result;
            }

            i += 1;
        }
        
        AttackLog::Result(&result, i.into()).log();
        
        result
    }
}
