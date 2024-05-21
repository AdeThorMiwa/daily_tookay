use std::time::Duration;

use crate::domain::{address::Address, vault::Vault};

pub struct CreateVaultOpts<'a> {
    release_value: u32,
    release_interval_in_sec: u64,
    recieving_address: &'a str,
    change_interval_in_sec: u64,
    change_address: &'a str,
}

pub fn create_vault(owner: &str, options: CreateVaultOpts) -> Result<Vault, ()> {
    let owner: Address = owner.try_into().expect("invalid owner address");
    let next_vault_index = 0; // TODO: get from db

    let release_address: Address = options
        .recieving_address
        .try_into()
        .expect("invalid receiving address");

    let change_address: Address = options
        .change_address
        .try_into()
        .expect("invalid change address");

    Vault::new(
        owner,
        next_vault_index,
        options.release_value,
        Duration::from_secs(options.release_interval_in_sec),
        Some(release_address),
        Duration::from_secs(options.change_interval_in_sec),
        Some(change_address),
    )
    .map_err(|_| ())
}
