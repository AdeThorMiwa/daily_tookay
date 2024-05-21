use std::time::Duration;

use super::address::Address;

pub struct Vault {
    pub(crate) id: u32,
    /// owner of the vault
    ///
    /// only this address is allowed to perform major operations on this vault
    pub(crate) owner: Address,

    /// smart contract associated to the vault
    ///
    /// this contract address points to the onchain vault
    pub(crate) vault_address: Address,

    /// value to release at a particular interval
    pub(crate) release_value: u32,

    /// the `release_value` will be sent to `release_address`
    /// at every release interval
    ///
    /// i.e `release_value=10` will be sent to `release_address`
    /// at every 12 hours
    pub(crate) release_interval: Duration,

    /// the address to release `release_value` to
    pub(crate) release_address: Address,

    /// after this duration elapse, the remaining balance of the vault
    /// will be sent to the `change_address`
    pub(crate) change_interval: Duration,

    /// the address to send the change to
    pub(crate) change_address: Address,

    /// addresses allowed to spend from this vault balance
    pub(crate) authorized_spenders: Vec<Address>,

    pub(crate) is_deployed: bool,
}
