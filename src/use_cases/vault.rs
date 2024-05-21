pub mod vault {
    use std::time::Duration;

    use crate::domain::{address::Address, vault::Vault};

    pub enum NewVaultError {}
    pub enum RequestReleaseError {}

    impl Vault {
        pub fn new(
            owner: Address,
            id: u32,
            release_value: u32,
            release_interval: Duration,
            release_address: Option<Address>,
            change_interval: Duration,
            change_address: Option<Address>,
        ) -> Result<Self, NewVaultError> {
            let vault_address = owner.get_vault_address(id);
            // TODO: connect to contract with address
            // get all this details from contract and use
            Ok(Self {
                id,
                owner: owner.clone(),
                vault_address,
                release_value,
                release_interval,
                release_address: release_address.unwrap_or(owner.clone()),
                change_interval,
                change_address: change_address.unwrap_or(owner),
                authorized_spenders: Vec::new(),
                is_deployed: false,
            })
        }

        /// https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract
        pub fn request_release(&self, _secret: u128) -> Result<(), RequestReleaseError> {
            // TODO: sha3 (secret, self.owner.getAddress())
            // run some validations (has request duration pass, no pending request...et.c)
            // send sha3 value to contract
            Ok(())
        }

        pub fn confirm_release(&self, _secret: u128) {
            //TODO: send secret to contract and contract verify if sha3(secret, msg.sender) is current_request_hash
        }

        pub fn balance(&self) -> u32 {
            0
        }
    }
}
