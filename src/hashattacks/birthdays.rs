use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use crossbeam::channel;
use log::{info, trace};

use crate::messagehash::HashValue;

use super::{AttackResult, AttackState, HashAttack, MessageHash};


const MIN_INDEX_RANGE_PER_THREAD: usize = 10000;

// Helper function (alias).
fn log_success(
    thread_id: u64,
    messagehash1: &MessageHash,
    messagehash2: &MessageHash,
    iteration1: u128,
    iteration2: u128
) {
    info!(
        "SUCCESS, Thread: {}, Iteration: {}-{}, \
         Message1: \"{}\", Hash1: {}, \
         Message2: \"{}\", Hash2: {}",
         thread_id,
         iteration1,
         iteration2,
         messagehash1.message(),
         messagehash1.hash_value(),
         messagehash2.message(),
         messagehash2.hash_value()
    );
}

// Helper function (alias).
fn log_term(
    function: &str,
    thread_id: u64,
    iteration1: u128,
    iteration2: u128
) {
    info!(
        "TERM, Function: {}, Thread: {}, Iteration: {}-{}", 
        function,
        thread_id, 
        iteration1,
        iteration2
    );
}

fn get_last_element<T>(elements: &Vec<T>) -> Option<&T> {
    let elements_number = elements.len();

    if elements_number == 0 {
        return None;
    }

    let last_element_index = elements.len() - 1;
    let last_element = &elements[last_element_index];

    Some(last_element)
}


pub struct Birthdays {
    thread_count: u64,
    state: AttackState,
    hash_size_in_bytes: usize,
    success_probability: f64,
    verbose_tries_number: u128,
    max_iters: u128
}

impl Birthdays {
    pub fn build(
        thread_count: u64,
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        success_probability: f64,
        verbose_tries_number: u128,
        max_iters: u128
    ) -> Result<Self, &'static str> {
        if thread_count == 0 {
            return Err("Number of threads can not be zero");
        }
        if hash_size_in_bytes > HashValue::len() {
            return Err("Provided hash size is too large");
        }
        if max_iters != 0 && max_iters < verbose_tries_number {
            return Err("Number of verbose tries exceeds the maximum number");
        }

        Ok(Self {
            thread_count,
            state: initial_state,
            hash_size_in_bytes,
            success_probability,
            verbose_tries_number,
            max_iters
        })
    }

    fn tries_from_probability(&self) -> u128 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count: u64 = 1 << hash_size_in_bits;
        let probability = self.success_probability;

        let count_part = (2.0 * hash_count as f64).sqrt(); 
        let ln_part = ((1.0 / (1.0 - probability)).ln() as f64).sqrt();
        
        (count_part * ln_part).ceil() as u128
    }
  
    fn search_collision(
        &self,
        calculated_hashes: &Vec<MessageHash>,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        let messagehash1 = match get_last_element(calculated_hashes) {
            Some(last_messagehash) => last_messagehash,
            None => return AttackResult::GeneralFailure("Empty vector passed")
        };
       
        let hashes_number = calculated_hashes.len();
        let index_range = hashes_number / self.thread_count as usize;
        let iteration1 = hashes_number as u128;
        
        // Number of threads depends on the number of calculated hashes, 
        // because there is no need to spawn 10 threads to process 10 hashes.
        let thread_count = if index_range < MIN_INDEX_RANGE_PER_THREAD {
            (hashes_number / MIN_INDEX_RANGE_PER_THREAD) as u64
        } else {
            self.thread_count
        };
        
        let (sender, receiver) = channel::bounded(self.thread_count as usize);
        
        crossbeam::scope(|scope| {
            for t in 1..=thread_count {
                let thread_sender = sender.clone();
                let thread_running = Arc::clone(&running);

                scope.spawn(move |_| {
                    let start_index = ((t as usize - 1) * index_range) as usize;
                    let end_index = start_index + index_range;
                   
                    let (result, iteration2) = self.search_collision_in_thread(
                        &calculated_hashes[start_index..end_index],
                        messagehash1,
                        thread_running
                    );
                   
                    let iterations = (iteration1, iteration2); 

                    let _ = thread_sender.send((t, result, iterations));
                });
            }

            // Close the channel to exit receiving for-loop.
            drop(sender);

            let result = Self::recv_thread_results(
                receiver,
                Arc::clone(&running)
            );

            result
        }).unwrap()
    }

    fn search_collision_in_thread(
        &self,
        hashes_range: &[MessageHash],
        messagehash1: &MessageHash,
        running: Arc<AtomicBool>
    ) -> (AttackResult, u128) {
        for (i, messagehash2) in hashes_range.iter().enumerate() {
            let iteration = i as u128 + 1;

            if !running.load(Ordering::SeqCst) {
                let result = AttackResult::GeneralFailure("Attack terminated");

                return (result, iteration);
            }

            if messagehash1.collides_with(
                messagehash2, 
                self.hash_size_in_bytes
            ) {
                let result = AttackResult::CollisionSuccess(
                    messagehash1.clone(),
                    messagehash2.clone()
                );
            
                return (result, iteration);
            }
        }

        let result = AttackResult::GeneralFailure("Failed to find collision");
        let iteration = hashes_range.len() as u128;

        (result, iteration)
    }
    
    fn recv_thread_results(
        receiver: channel::Receiver<(u64, AttackResult, (u128, u128))>,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        for received in receiver.iter() {
            let (thread_id, result, (i, j)) = received;

            match result {
                // Return the first found collision.
                AttackResult::CollisionSuccess(ref mh1, ref mh2) => {
                    // Terminate other threads.
                    running.store(false, Ordering::Relaxed);

                    log_success(thread_id, mh1, mh2, i, j);

                    return result;
                },
                AttackResult::GeneralFailure("Attack terminated") => {
                    log_term(
                        "BruteForce::search_collision_in_thread", 
                        thread_id, 
                        i,
                        j
                    );
                }
                _ => ()
            };
        }

        AttackResult::GeneralFailure("Failed to find collision")
    }
    
    fn search_collision_verbose(
        &self,
        calculated_hashes: &Vec<MessageHash>,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        let result = self.search_collision(
            calculated_hashes,
            running
        );

        let messagehash1 = match get_last_element(calculated_hashes) {
            Some(last_messagehash) => last_messagehash,
            None => return result
        };
        let messagehash2 = calculated_hashes.get(0).unwrap();

        trace!("{}, {}", messagehash1, messagehash2);

        result
    }   
   
    fn try_find_collision(
        &mut self,
        calculated_hashes: &mut Vec<MessageHash>,
        start_iter: u128,
        end_iter: u128,
        verbose: bool,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        let search_func = if verbose {
            Self::search_collision_verbose
        } else {
            Self::search_collision
        };

        for i in start_iter..=end_iter {
            if !running.load(Ordering::SeqCst) {
                log_term("Birthdays::try_find_collision", 0, i, 0);
                return AttackResult::GeneralFailure("Attack terminated");
            }

            let messagehash = self.state.messagehash_with_transform();
            calculated_hashes.push(messagehash);
          
            let result = search_func(
                self,
                calculated_hashes,
                Arc::clone(&running)
            ); 

            if let AttackResult::CollisionSuccess(_, _) = result {
                return result;
            }
        }

        AttackResult::GeneralFailure("Failed to find collision")
    }
}

impl HashAttack for Birthdays {
    fn initial_state(&self) -> &AttackState {
        &self.state
    }
    fn initial_state_mut(&mut self) -> &mut AttackState {
        &mut self.state
    }
    
    fn attack(
        &mut self,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        let initial_messagehash = self.state.messagehash();

        info!(
            "INIT, Message: \"{}\", Hash: {}",
            initial_messagehash.message(), 
            initial_messagehash.hash_value()
        );
        
        let mut calculated_hashes = vec![initial_messagehash];

        let verbose_result = self.try_find_collision(
            &mut calculated_hashes,
            1,
            self.verbose_tries_number,
            true,
            Arc::clone(&running)
        );
        
        if verbose_result.is_success() {
            return verbose_result;
        }

        let expected_tries_number = self.tries_from_probability();
        let tries_number = if self.max_iters <= expected_tries_number {
            self.max_iters
        } else {
            expected_tries_number
        };

        let silent_result = self.try_find_collision(
            &mut calculated_hashes,
            self.verbose_tries_number + 1,
            tries_number - self.verbose_tries_number,
            false,
            Arc::clone(&running)
        );

        if !silent_result.is_success() {
            info!("FAILURE, Iteration: {}-{}", tries_number, tries_number);
        }

        return silent_result;
    }
}
