use ethers::types::U256;
use sha3::{Digest, Keccak256};

/// Externally owned Address
#[derive(Clone)]
pub struct Address(ethers::prelude::Address);

#[derive(Debug)]
pub enum AddressError {
    ParseError,
}

impl TryFrom<&str> for Address {
    type Error = AddressError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let address: ethers::prelude::Address =
            value.parse().map_err(|_| AddressError::ParseError)?;
        Ok(Self(address))
    }
}

impl Address {
    pub fn get_vault_address(&self, id: u32) -> Address {
        // TODO: init code
        let salt = Self::u32_to_u256_bytes(id);
        let address = self.create2(&salt, &[]);
        let address: ethers::prelude::Address = address.as_str().parse().unwrap();
        Address(address)
    }

    fn u32_to_u256_bytes(v: u32) -> [u8; 32] {
        let u256_v = U256::from(v);
        let mut u256_v_buf: [u8; 32] = [0; 32];
        u256_v.to_big_endian(&mut u256_v_buf);
        u256_v_buf
    }

    // update to use ethers lib
    fn create2(&self, salt: &[u8; 32], init_code: &[u8]) -> String {
        let address: &[u8; 20] = &self.0.to_fixed_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(init_code);

        let mut code_hash = [0; 32];
        code_hash.copy_from_slice(&hasher.finalize());

        let mut buf = [0; 85];

        buf[0] = 0xFF;
        buf[1..21].copy_from_slice(address);
        buf[21..53].copy_from_slice(salt);
        buf[53..85].copy_from_slice(&code_hash);

        let mut hasher = Keccak256::new();
        hasher.update(&buf[..]);

        let mut ret = [0; 20];
        ret.copy_from_slice(&hasher.finalize()[12..32]);
        String::from_utf8(ret.to_vec()).expect("unable to convert bytes to string")
    }
}
