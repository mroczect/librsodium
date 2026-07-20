use libsodium_rs::crypto_core::keccak1600 as lib_keccak;

pub const STATEBYTES: usize = lib_keccak::STATEBYTES;

pub fn statebytes() -> usize {
    lib_keccak::statebytes()
}

pub struct State {
    inner: lib_keccak::State,
}

impl State {
    pub fn new() -> Self {
        Self {
            inner: lib_keccak::State::new(),
        }
    }

    pub fn init(&mut self) {
        self.inner.init();
    }

    pub fn xor_bytes(&mut self, bytes: &[u8], offset: usize) {
        self.inner.xor_bytes(bytes, offset);
    }

    pub fn extract_bytes(&self, bytes: &mut [u8], offset: usize) {
        self.inner.extract_bytes(bytes, offset);
    }

    pub fn permute_24(&mut self) {
        self.inner.permute_24();
    }

    pub fn permute_12(&mut self) {
        self.inner.permute_12();
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
