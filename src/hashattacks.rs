use std::{
    sync::{atomic::{AtomicBool, Ordering}, Arc},
    time
};

use chrono::prelude::*;
use ripemd::{Digest, Ripemd160};

use crate::messagehash::{HashValue, MessageHash};
use messagetransform::MessageTransform;


pub mod birthdays;
pub mod bruteforce;
pub mod hellman;
pub mod messagetransform;


pub trait HashAttack {
    fn attack(&mut self, running: Arc<AtomicBool>) -> AttackResult;
    
    fn execute(&mut self) -> AttackResult {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc_async::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");

        let mut utc: DateTime<Utc> = Utc::now();
        println!("[TIME] Attack began at {}", utc);
        let now = time::Instant::now();

        let result = self.attack(running);

        let elapsed_time = now.elapsed();

        utc = Utc::now();
        println!("[TIME] Attack finished at {}", utc);
        println!("[TIME] Attack took {:.2?}", elapsed_time);

        result
    }
}

#[derive(Clone, Debug)]
pub enum AttackResult {
    Preimage(String),
    Collision(String, String),
    Failure,
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

    pub fn messagehash(&mut self) -> MessageHash {
        self.hasher.update(&self.message);

        MessageHash::new(
            &self.message,
            HashValue::new(self.hasher.finalize_reset())
        ) 
    }

    pub fn hash_message(&mut self, message: &[u8]) -> HashValue {
        self.hasher.update(&message);

        HashValue::new(self.hasher.finalize_reset())
    }

    pub fn update(&mut self) -> MessageHash {
        let modified_message = self.message_transform.transform(&self.message);
       
        self.hasher.update(&modified_message);

        let modified_hash = HashValue::new(self.hasher.finalize_reset());

        MessageHash::new(&modified_message, modified_hash)
    }
}
