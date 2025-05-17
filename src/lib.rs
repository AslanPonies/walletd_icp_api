use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use std::collections::HashMap;

/// Represents an ICP wallet with a principal, subaccount, and balance.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Wallet {
    principal: Option<Principal>,
    subaccount: Option<Vec<u8>>,
    balance: u64,
}

/// Supported cryptocurrencies for cross-chain swaps.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum Coin {
    Bitcoin,
    Monero,
    Solana,
    Ethereum,
    Hedera,
}

/// Errors for ICP wallet operations.
#[derive(Debug)]
pub enum IcpWalletError {
    WalletNotFound,
    InsufficientFunds,
    Custom(String),
}

/// Trait defining asynchronous wallet operations for ICP and cross-chain interactions.
#[async_trait]
pub trait WalletDApi {
    /// Generates a new wallet address.
    async fn generate_address(&mut self) -> Result<String, IcpWalletError>;
    /// Retrieves the balance for a given principal.
    async fn get_balance(&self, principal: &str) -> Result<u64, IcpWalletError>;
    /// Transfers ICP from one principal to another.
    async fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<String, IcpWalletError>;
    /// Approves a spender to transfer ICP on behalf of a principal.
    async fn approve(&mut self, from: &str, spender: &str, amount: u64) -> Result<String, IcpWalletError>;
    /// Transfers ICP from one principal to another after approval.
    async fn transfer_from(&mut self, spender: &str, from: &str, to: &str, amount: u64) -> Result<String, IcpWalletError>;
    /// Performs batch transfers from a single principal to multiple recipients.
    async fn batch_transfer(&mut self, from: &str, transfers: Vec<(String, u64)>) -> Result<String, IcpWalletError>;
    /// Swaps ICP to another cryptocurrency.
    async fn swap_icp_to_coin(&mut self, from: &str, to: &str, amount: u64, coin: Coin) -> Result<String, IcpWalletError>;
    /// Calls a canister method with specified arguments.
    async fn call_canister(&self, canister_id: &str, method: &str, args: &str) -> Result<String, IcpWalletError>;
}

/// Implementation of the ICP wallet API.
pub struct WalletDIcpApi {
    wallets: HashMap<String, Wallet>,
    locked: bool,
}

impl WalletDIcpApi {
    /// Creates a new test instance of `WalletDIcpApi`.
    pub fn new_test() -> Result<Self, IcpWalletError> {
        Ok(Self {
            wallets: HashMap::new(),
            locked: false,
        })
    }
}

#[async_trait]
impl WalletDApi for WalletDIcpApi {
    async fn generate_address(&mut self) -> Result<String, IcpWalletError> {
        Ok("gqud4-oc6ie-tpkta-n3bsd-p2hmx-rkqzb-p3nit-l55bf-u66oh-rbdqo-xae".to_string())
    }

    async fn get_balance(&self, principal: &str) -> Result<u64, IcpWalletError> {
        let wallet = self.wallets.get(principal).ok_or(IcpWalletError::WalletNotFound)?;
        Ok(wallet.balance)
    }

    async fn transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<String, IcpWalletError> {
        if self.locked {
            return Err(IcpWalletError::Custom("Re-entrant call detected".to_string()));
        }
        self.locked = true;
        let wallet = self.wallets.get_mut(from).ok_or(IcpWalletError::WalletNotFound)?;
        if wallet.balance < amount {
            self.locked = false;
            return Err(IcpWalletError::InsufficientFunds);
        }
        wallet.balance -= amount;
        self.locked = false;
        Ok(format!("Transferred {} ICP to {}", amount, to))
    }

    async fn approve(&mut self, _from: &str, _spender: &str, amount: u64) -> Result<String, IcpWalletError> {
        Ok(format!("Approved {} ICP for {}", amount, _spender))
    }

    async fn transfer_from(&mut self, _spender: &str, from: &str, to: &str, amount: u64) -> Result<String, IcpWalletError> {
        if self.locked {
            return Err(IcpWalletError::Custom("Re-entrant call detected".to_string()));
        }
        self.locked = true;
        let wallet = self.wallets.get_mut(from).ok_or(IcpWalletError::WalletNotFound)?;
        if wallet.balance < amount {
            self.locked = false;
            return Err(IcpWalletError::InsufficientFunds);
        }
        wallet.balance -= amount;
        self.locked = false;
        Ok(format!("Transferred {} ICP from {} to {}", amount, from, to))
    }

    async fn batch_transfer(&mut self, from: &str, transfers: Vec<(String, u64)>) -> Result<String, IcpWalletError> {
        if self.locked {
            return Err(IcpWalletError::Custom("Re-entrant call detected".to_string()));
        }
        self.locked = true;
        let wallet = self.wallets.get_mut(from).ok_or(IcpWalletError::WalletNotFound)?;
        let total_amount: u64 = transfers.iter().map(|(_, amount)| *amount).sum();
        if wallet.balance < total_amount {
            self.locked = false;
            return Err(IcpWalletError::InsufficientFunds);
        }
        wallet.balance -= total_amount;
        self.locked = false;
        Ok(format!("Batch transferred from {}: {:?}", from, transfers))
    }

    async fn swap_icp_to_coin(&mut self, from: &str, to: &str, amount: u64, coin: Coin) -> Result<String, IcpWalletError> {
        if to.is_empty() {
            return Err(IcpWalletError::Custom("Empty address provided".to_string()));
        }
        if amount == 0 {
            return Err(IcpWalletError::Custom("Amount must be greater than zero".to_string()));
        }
        if self.locked {
            return Err(IcpWalletError::Custom("Re-entrant call detected".to_string()));
        }
        self.locked = true;
        let wallet = self.wallets.get_mut(from).ok_or(IcpWalletError::WalletNotFound)?;
        if wallet.balance < amount {
            self.locked = false;
            return Err(IcpWalletError::InsufficientFunds);
        }
        let coin_name = match coin {
            Coin::Bitcoin => "BTC",
            Coin::Monero => "XMR",
            Coin::Solana => "SOL",
            Coin::Ethereum => "ETH",
            Coin::Hedera => "HBAR",
        };
        wallet.balance -= amount;
        self.locked = false;
        Ok(format!("Swapped {} ICP to {} {}", amount, coin_name, to))
    }

    async fn call_canister(&self, canister_id: &str, method: &str, args: &str) -> Result<String, IcpWalletError> {
        Ok(format!("Canister {} called with method {} and args {}", canister_id, method, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_address() {
        let mut wallet = WalletDIcpApi::new_test().unwrap();
        let address = wallet.generate_address().await.unwrap();
        assert!(!address.is_empty());
    }
}