use std::collections::HashMap;

use ed25519_compact::{PublicKey, SecretKey, Signature};

use crate::sig_hash_circuit::make_hash;

#[derive(Clone)]
pub struct Block {
    nonce: usize,
    height: usize,
    prev_hash: String,
    hash: String,
    epoch_id: String,
    pub sig: Signature,
    pub validators_sig: [Signature; 3],
}
#[derive(Clone)]
pub struct EpochBlock {
    nonce: usize,
    height: usize,
    prev_hash: String,
    hash: String,
    epoch_id: String,
    pub sig: Signature,
    pub validators_sig: [Signature; 3],
    pub validators_pk: HashMap<usize, PublicKey>,
}
impl EpochBlock {
    pub fn get_v_pk(&self) -> HashMap<usize, PublicKey> {
        self.validators_pk.clone()
    }
    pub fn set_v_pk(&mut self, users: HashMap<u32, (PublicKey, SecretKey)>) {
        for j in 0..users.len() {
            self.validators_pk
                .insert(j, users.get(&(j as u32)).unwrap().0);
        }
    }
}
#[derive(Clone)]
pub enum BlockType {
    Block(Block),
    EpochBlock(EpochBlock),
}
impl BlockType {
    pub fn get_nonce(&self) -> usize {
        match *self {
            BlockType::Block(ref s) => s.nonce,
            BlockType::EpochBlock(ref p) => p.nonce,
        }
    }
    pub fn get_height(&self) -> usize {
        match *self {
            BlockType::Block(ref s) => s.height,
            BlockType::EpochBlock(ref p) => p.height,
        }
    }
    pub fn get_prev_hash(&self) -> String {
        match *self {
            BlockType::Block(ref s) => s.prev_hash.clone(),
            BlockType::EpochBlock(ref p) => p.prev_hash.clone(),
        }
    }
    pub fn get_hash(&self) -> String {
        match *self {
            BlockType::Block(ref s) => s.hash.clone(),
            BlockType::EpochBlock(ref p) => p.hash.clone(),
        }
    }
    pub fn get_epoch_id(&self) -> String {
        match *self {
            BlockType::Block(ref s) => s.epoch_id.clone(),
            BlockType::EpochBlock(ref p) => p.epoch_id.clone(),
        }
    }
    pub fn get_sig(&self) -> Signature {
        match *self {
            BlockType::Block(ref s) => s.sig,
            BlockType::EpochBlock(ref p) => p.sig,
        }
    }
    pub fn get_v_sig(&self) -> [Signature; 3] {
        match *self {
            BlockType::Block(ref s) => s.validators_sig,
            BlockType::EpochBlock(ref p) => p.validators_sig,
        }
    }
    pub fn get_v_pk(&self) -> Option<HashMap<usize, PublicKey>> {
        match *self {
            BlockType::EpochBlock(ref p) => Some(p.validators_pk.clone()),
            BlockType::Block(_) => Option::None,
        }
    }
}

pub trait Data {
    fn new() -> Self
    where
        Self: Sized;
    fn set(
        &mut self,
        nonce: usize,
        height: usize,
        prev_hash: String,
        epoch_id: String,
        users: HashMap<u32, (PublicKey, SecretKey)>,
    );
}
impl Data for Block {
    fn new() -> Block {
        Block {
            nonce: 0,
            height: 0,
            prev_hash: String::new(),
            hash: String::new(),
            epoch_id: String::new(),
            sig: Signature::new([0; 64]),
            validators_sig: [Signature::new([0; 64]); 3],
        }
    }
    fn set(
        &mut self,
        nonce: usize,
        height: usize,
        prev_hash: String,
        epoch_id: String,
        users: HashMap<u32, (PublicKey, SecretKey)>,
    ) {
        self.nonce = nonce;
        self.height = height;
        self.prev_hash = prev_hash;
        let msg = self.prev_hash.clone() + &self.nonce.to_string();
        let hash = make_hash(msg.as_bytes());
        self.hash = hash;
        self.epoch_id = epoch_id;
        // nonce % 2 - there are two block producers
        self.sig = users
            .get(&((nonce % 2) as u32))
            .unwrap()
            .1
            .sign(self.nonce.to_string(), None);
        let mut validators_sig: [Signature; 3] = [Signature::new([0; 64]); 3];
        for i in 0..users.len() {
            validators_sig[i] = users
                .get(&(i as u32))
                .unwrap()
                .1
                .sign(self.nonce.to_string(), None);
        }
        self.validators_sig = validators_sig;
    }
}
impl Data for EpochBlock {
    fn new() -> EpochBlock {
        EpochBlock {
            nonce: 0,
            height: 0,
            prev_hash: String::new(),
            hash: String::new(),
            epoch_id: String::new(),
            sig: Signature::new([0; 64]),
            validators_sig: [Signature::new([0; 64]); 3],
            validators_pk: HashMap::new(),
        }
    }
    fn set(
        &mut self,
        nonce: usize,
        height: usize,
        prev_hash: String,
        epoch_id: String,
        users: HashMap<u32, (PublicKey, SecretKey)>,
    ) {
        self.nonce = nonce;
        self.height = height;
        self.prev_hash = prev_hash;
        let msg = self.prev_hash.clone() + &self.nonce.to_string();
        let hash = make_hash(msg.as_bytes());
        self.hash = hash;
        self.epoch_id = epoch_id;
        // nonce % 2 - there are two block producers
        self.sig = users
            .get(&((nonce % 2) as u32))
            .unwrap()
            .1
            .sign(self.nonce.to_string(), None);
        let mut validators_sig: [Signature; 3] = [Signature::new([0; 64]); 3];
        for i in 0..users.len() {
            validators_sig[i] = users
                .get(&(i as u32))
                .unwrap()
                .1
                .sign(self.nonce.to_string(), None);
        }
        self.validators_sig = validators_sig;
        self.set_v_pk(users);
    }
}
