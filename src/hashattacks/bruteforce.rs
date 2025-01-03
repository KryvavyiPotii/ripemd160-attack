use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use crossbeam::channel; 
use log::{info, trace};

use crate::{messagehash::{HashValue, MessageHash}, MessageTransform};

use super::{AttackResult, AttackState, HashAttack};


fn equal_hashes(
    messagehash1: &MessageHash,
    messagehash2: &MessageHash,
    hash_size_in_bytes: usize
) -> bool {
    messagehash1
        .hash_value()
        .equal_to(
            messagehash2.hash_value(),
            hash_size_in_bytes
        )
}

// Helper function (alias).
fn log_success(
    thread_id: u64,
    iteration: u128,
    preimage: &MessageHash
) {
    info!(
        "SUCCESS, Thread: {}, Iteration: {}, \
        Preimage: \"{}\", Preimage hash: {}",
        thread_id,
        iteration,
        preimage.message(),
        preimage.hash_value()
    );
}

// Helper function (alias).
fn log_term(
    function: &str,
    thread_id: u64,
    iteration: u128
) {
    info!(
        "TERM, Function: {}, Thread: {}, Iteration: {}", 
        function,
        thread_id, 
        iteration
    );
}

// Find iteration bounds for BruteForce::try_find_preimage method.
fn get_thread_iter_bounds(
    thread_count: u64,
    thread_id: u64,
    start_iter: u128,
    end_iter: u128
) -> (u128, u128) {
    let tries_number = end_iter - start_iter;
    let range_size = tries_number / thread_count as u128;
    let offset = (thread_id as u128 - 1) * range_size;
    
    let start_iter = start_iter + offset;
    let end_iter = start_iter + range_size;

    (start_iter, end_iter)
}


#[derive(Clone)]
pub struct BruteForce {
    thread_count: u64,
    state: AttackState,
    hash_size_in_bytes: usize,
    success_probability: f64,
    verbose_tries_number: u128
}

impl BruteForce {
    pub fn build(
        thread_count: u64,
        initial_state: AttackState,
        hash_size_in_bytes: usize,
        success_probability: f64,
        verbose_tries_number: u128
    ) -> Result<Self, &'static str> {
        if thread_count == 0 {
            return Err("Number of threads can not be zero");
        }
        if hash_size_in_bytes > HashValue::len() {
            return Err("Provided hash size is too large");
        }

        Ok(Self {
            thread_count,
            state: initial_state,
            hash_size_in_bytes,
            success_probability,
            verbose_tries_number
        })
    }

    fn tries_from_probability(&self) -> u128 {
        let hash_size_in_bits = self.hash_size_in_bytes * 8; 
        let hash_count: u128 = 1 << hash_size_in_bits;
        let probability = self.success_probability;
        
        hash_count * (1.0 / (1.0 - probability)).ln().ceil() as u128
    }

    // Change start number for AppendNumberInSequence.
    fn config_transform(
        &mut self,
        start_number: u128
    ) -> Result<(), ()> {
        let transform = self.state.get_mut_message_transform();
        transform.set_start_number(start_number)
    }

    fn decide_to_split_tries(&self, verbose: bool) -> bool {
        let transform = self.state.get_message_transform();

        let number_in_sequence = match transform {
            MessageTransform::AppendNumberInSequence(_) => true,
            _ => false
        };
        
        number_in_sequence || verbose
    }

    fn search_preimage(
        &mut self,
        initial_messagehash: Arc<MessageHash>
    ) -> AttackResult {
        let messagehash = self.state.messagehash_with_transform();
        
        if equal_hashes(
            &initial_messagehash, 
            &messagehash,
            self.hash_size_in_bytes
        ) {
            return AttackResult::PreimageSuccess(messagehash);
        }

        AttackResult::PreimageFailure(messagehash)
    }
    
    fn search_preimage_verbose(
        &mut self,
        initial_messagehash: Arc<MessageHash>
    ) -> AttackResult {
        let result = self.search_preimage(
            Arc::clone(&initial_messagehash)
        );
    
        match result {
            AttackResult::PreimageSuccess(ref messagehash) => 
                trace!("{}", messagehash),
            AttackResult::PreimageFailure(ref messagehash) => 
                trace!("{}", messagehash),
            _ => ()
        };

        result
    }

    fn try_find_preimage<F>(
        &mut self,
        start_iter: u128,
        end_iter: u128,
        initial_messagehash: Arc<MessageHash>,
        search_func: F,
        running: Arc<AtomicBool>
    ) -> (AttackResult, u128)
    where
        F: Fn(&mut Self, Arc<MessageHash>) -> AttackResult
    {
        for i in start_iter..=end_iter {
            if !running.load(Ordering::SeqCst) {
                return (AttackResult::GeneralFailure("Attack terminated"), i);
            }
          
            let result = search_func(
                self,
                Arc::clone(&initial_messagehash)
            ); 

            if let AttackResult::PreimageSuccess(_) = result {
                let iteration = i;

                return (result, iteration);
            }
        }

        let result = AttackResult::GeneralFailure("Failed to find preimage");
        let iteration = end_iter;

        (result, iteration)
    }

    fn attack_in_parallel(
        &mut self,
        initial_messagehash: Arc<MessageHash>,
        start_iter: u128,
        end_iter: u128,
        verbose: bool,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        if start_iter > end_iter {
            return AttackResult::GeneralFailure("Invalid iterations");
        }
        
        let (sender, receiver) = channel::bounded(self.thread_count as usize);
        let thread_count = self.thread_count;

        let split_tries = self.decide_to_split_tries(verbose);
        let search_func = if verbose {
            Self::search_preimage_verbose
        } else {
            Self::search_preimage
        };
        
        crossbeam::scope(|scope| {
            for t in 1..=thread_count {
                // TODO find more elegant solution without cloning
                // Currently cloning is necessary because &mut self is required
                // in order to get hash value. The reason for that lies in
                // architecture of ripemd crate that does not allow calculating
                // hash by, for example, simply calling some get_ripemd160 
                // function.
                let mut thread_self = self.clone();
                let thread_sender = sender.clone();
                let running = Arc::clone(&running);
                let initial_messagehash = Arc::clone(&initial_messagehash);

                scope.spawn(move |_| { 
                    let (start_iter, end_iter) = if split_tries { 
                        let (start, end) = get_thread_iter_bounds(
                            thread_count,
                            t,
                            start_iter,
                            end_iter
                        );
                        let _ = thread_self.config_transform(start);

                        (start, end)
                    } else {
                        (start_iter, end_iter)
                    };

                    let (result, iteration) = thread_self.try_find_preimage(
                        start_iter,
                        end_iter,
                        initial_messagehash,
                        search_func,
                        running
                    );

                    let _ = thread_sender.send((t, result, iteration));
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

    fn recv_thread_results(
        receiver: channel::Receiver<(u64, AttackResult, u128)>,
        running: Arc<AtomicBool>
    ) -> AttackResult {
        for received in receiver.iter() {
            let (thread_id, result, iteration) = received;

            match result {
                // Return the first found preimage.
                AttackResult::PreimageSuccess(ref preimage) => {
                    // Terminate other threads.
                    running.store(false, Ordering::Relaxed);

                    log_success(thread_id, iteration, preimage);
                    return result;
                },
                AttackResult::GeneralFailure("Attack terminated") => {
                    log_term(
                        "BruteForce::attack_in_parallel", 
                        thread_id, 
                        iteration
                    );
                }
                _ => ()
            };
        }

        AttackResult::GeneralFailure("Failed to find preimage")
    }
}

impl HashAttack for BruteForce {
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
        let initial_messagehash = Arc::new(self.state.messagehash());

        info!(
            "INIT, Message: \"{}\", Hash: {}",
            initial_messagehash.message(), 
            initial_messagehash.hash_value()
        );

        let verbose_result = self.attack_in_parallel(
            Arc::clone(&initial_messagehash),
            1,
            self.verbose_tries_number,
            true,
            Arc::clone(&running)
        );
        
        if verbose_result.is_success() {
            return verbose_result;
        }

        let silent_result = self.attack_in_parallel(
            Arc::clone(&initial_messagehash),
            self.verbose_tries_number + 1,
            self.tries_from_probability() - self.verbose_tries_number,
            false,
            Arc::clone(&running)
        );

        return silent_result;
    }
}
