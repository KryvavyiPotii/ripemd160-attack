use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use log::info;
use ripemd::{Digest, Ripemd160};

use crate::messagehash::{HashValue, MessageHash};

use messagetransform::MessageTransform;


pub mod birthdays;
pub mod bruteforce;
pub mod hellman;
pub mod messagetransform;


pub trait HashAttack {
    fn initial_state(&self) -> &AttackState;
    fn initial_state_mut(&mut self) -> &mut AttackState;
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult;

    fn execute(
        &mut self, 
        attack_count: u64,
        transform_message: bool
    ) -> Vec<AttackResult> {
        let running = set_ctrlc_handler();

        let mut results = Vec::with_capacity(attack_count as usize);
        let initial_message = self.initial_state().message.clone();

        for i in 1..=attack_count {
            if !running.load(Ordering::SeqCst) {
                info!("TERM, Attack execution, Iteration: {}", i);
                break;
            }

            // Transform the initial message if needed.
            if transform_message {
                let state = self.initial_state_mut();
                let transformed_message = state.transform_message(
                    &initial_message
                );

                state.set_message(&transformed_message);
            }
            
            results.push(
                self.attack(running.clone())
            );

            // Restore initial message.
            self.initial_state_mut().set_message(&initial_message);
        }

        results
    }
}


fn set_ctrlc_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc_async::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    running
}


#[derive(Debug)]
pub enum AttackResult {
    GeneralFailure(&'static str),
    PreimageFailure(MessageHash),
    PreimageSuccess(MessageHash),
    CollisionSuccess(MessageHash, MessageHash)
}

impl AttackResult {
    pub fn is_success(&self) -> bool {
        match self {
            Self::PreimageSuccess(_) | Self::CollisionSuccess(_, _) => true,
            _ => false
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttackState {
    hasher: Ripemd160,
    message: String,
    message_transform: MessageTransform,
}

impl AttackState {
    pub fn new(
        message: &str,
        message_transform: MessageTransform
    ) -> Self {
        let hasher = Ripemd160::new();

        Self {
            hasher,
            message: message.to_string(),
            message_transform,
        }
    }

    pub fn set_message(&mut self, message: &str) {
        self.message = message.to_string();
    }

    pub fn get_mut_message_transform(&mut self) -> &mut MessageTransform {
        &mut self.message_transform
    }
    
    pub fn get_message_transform(&self) -> &MessageTransform {
        &self.message_transform
    }

    pub fn transform_message(&mut self, message: &str) -> String {
        let transformed_message = self.message_transform.transform(
            &message
        );

        transformed_message
    }

    pub fn messagehash(&mut self) -> MessageHash {
        self.hasher.update(&self.message);

        MessageHash::new(
            &self.message,
            HashValue::new(self.hasher.finalize_reset())
        ) 
    }
    
    pub fn messagehash_with_transform(&mut self) -> MessageHash {
        let modified_message = self.message_transform.transform(&self.message);
       
        self.hasher.update(&modified_message);

        let modified_hash = HashValue::new(self.hasher.finalize_reset());

        MessageHash::new(&modified_message, modified_hash)
    }

    pub fn hash_message(&mut self, message: &[u8]) -> HashValue {
        self.hasher.update(&message);

        HashValue::new(self.hasher.finalize_reset())
    }
}
