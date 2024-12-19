use std::{
    fmt,
    ops::{Index, Range, RangeFrom, RangeTo, RangeFull}
};

use generic_array::GenericArray;
use ripemd::{Ripemd160Core, digest::OutputSizeUser};


const HASH_SIZE_IN_BYTES: usize = 20;


type HashArray = GenericArray<
    u8,
    <Ripemd160Core as OutputSizeUser>::OutputSize
>;


fn get_suffix_index(hash_len: usize, suffix_len_in_bytes: usize) -> usize {
    if hash_len > suffix_len_in_bytes {
        hash_len - suffix_len_in_bytes
    }
    else {
        0
    }
}


#[derive(Clone, Debug)]
pub struct HashValue {
    pub hash: HashArray,
}

impl HashValue {
    pub fn new(hash: HashArray) -> Self {
        Self { hash }
    }
    
    pub fn len() -> usize {
        Ripemd160Core::output_size()
    }

    pub fn equal_to(&self, other: &Self, suffix_len_in_bytes: usize) -> bool {
        let hash_size = Self::len();

        let suffix_index1 = get_suffix_index(hash_size, suffix_len_in_bytes);
        let suffix_index2 = get_suffix_index(hash_size, suffix_len_in_bytes);

        self[suffix_index1..] == other[suffix_index2..] 
    }
}

impl From<&[u8; HASH_SIZE_IN_BYTES]> for HashValue {
    fn from(hash_array: &[u8; HASH_SIZE_IN_BYTES]) -> Self {
        let hash: HashArray = GenericArray::clone_from_slice(hash_array);

        Self { hash }
    }
}

impl fmt::LowerHex for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.hash)
    }
}

impl fmt::Display for HashValue {
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
        &self.hash.as_slice()
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

    pub fn hash_value(&self) -> &HashValue {
        &self.hash
    }

    pub fn message(&self) -> &String {
        &self.message
    }

    pub fn collides_with(
        &self,
        other: &Self,
        suffix_len_in_bytes: usize
    ) -> bool {
        let different_messages = self.message != other.message;
        let equal_hashes = self.hash.equal_to(
            &other.hash,
            suffix_len_in_bytes
        );

        different_messages && equal_hashes
    }
}

impl fmt::Display for MessageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} \"{}\"", self.hash, self.message)
    }
}
