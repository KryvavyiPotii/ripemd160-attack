use std::{
    fmt,
    ops::{Index, Range, RangeFrom, RangeTo, RangeFull}
};

use generic_array::GenericArray;
use ripemd::{Digest, Ripemd160, Ripemd160Core, digest::OutputSizeUser};


pub const HASH_SIZE_IN_BYTES: usize = 20;


pub type HashArray = GenericArray<
    u8,
    <Ripemd160Core as OutputSizeUser>::OutputSize
>;


#[derive(Clone, Debug)]
pub struct HashValue {
    pub hash: HashArray,
}

impl HashValue {
    pub fn new(hash: HashArray) -> Self {
        Self { hash }
    }
    
    pub fn len(&self) -> usize {
        Ripemd160Core::output_size()
    }
}

impl From<&[u8; HASH_SIZE_IN_BYTES]> for HashValue {
    fn from(hash_array: &[u8; HASH_SIZE_IN_BYTES]) -> Self {
        let hash: HashArray = GenericArray::clone_from_slice(hash_array);

        HashValue { hash }
    }
}

impl Into<[u8; HASH_SIZE_IN_BYTES]> for HashValue {
    fn into(self) -> [u8; HASH_SIZE_IN_BYTES] {
        self.hash.into()
    }
}

impl fmt::LowerHex for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.hash)
    }
}

impl Index<usize> for HashValue {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.hash[index]
    }
}

impl Index<RangeFull> for HashValue {
    type Output = [u8];

    fn index(&self, _index: RangeFull) -> &Self::Output {
        &self.hash
    }
}

impl Index<Range<usize>> for HashValue {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.hash[index]
    }
}

impl Index<RangeFrom<usize>> for HashValue {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.hash[index]
    }
}

impl Index<RangeTo<usize>> for HashValue {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.hash[index]
    }
}

#[derive(Clone, Debug)]
pub struct MessageHash {
    message: String,
    hash: HashValue,
}

impl MessageHash {
    pub fn new(message: &str, hash: HashValue) -> Self {
        Self { 
            message: message.to_string(),
            hash
        }
    }

    pub fn hash_message(hasher: &mut Ripemd160, message: &str) -> Self {
        let message = message.to_string();

        hasher.update(&message);

        Self {
            message,
            hash: HashValue::new(hasher.finalize_reset()),
        }
    }

    pub fn hash_value(&self) -> &HashValue {
        &self.hash
    }

    pub fn hash_len(&self) -> usize {
        self.hash.len()
    }

    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl fmt::Display for MessageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{:x}", self.message, self.hash)
    }
}
