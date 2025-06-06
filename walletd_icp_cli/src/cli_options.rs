use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use walletd_icp_api::{WalletDIcpApi, IcpWalletError, Coin};
use candid::Principal;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about = "WalletD ICP CLI: Manage cryptocurrency wallets with ICP 
integration", long_about = None)]
pub struct CliOptions {
    #[clap(subcommand)]
    pub command: Option<Command>,
    #[clap(long, short, help = "Network type: mainnet or testnet")]
    pub network: Option<String>,
    #[clap(long, short = 'w', help = "Number of words for mnemonic seed (12, 15, 18, 21, 24)")]
    pub specified_num_words: Option<u32>,
    #[clap(long, short, help = "Language for mnemonic seed (default: english)")]
    pub language: Option<String>,
    #[clap(long, short, help = "Path to config file")]
    pub config: Option<PathBuf>,
    #[clap(long, help = "Seed bytes (hex string) for wallet derivation")]
    pub seed: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    #[clap(about = "Generate a new key")]
    GenerateKey,
    #[clap(about = "Initialize wallet")]
    InitWallet {
        #[clap(subcommand)]
        coin: CoinType,
    },
    #[clap(about = "Show wallet address")]
    Address,
    #[clap(about = "Show wallet balance")]
    Balance,
    #[clap(about = "Transfer funds")]
    Transfer {
        #[clap(long, short, help = "Amount to transfer")]
        amount: f64,
        #[clap(long, short, help = "Recipient address")]
        to: String,
    },
    #[clap(about = "View transaction history")]
    Transactions,
    #[clap(about = "View transaction details")]
    TransactionDetails {
        #[clap(help = "Transaction hash")]
        hash: String,
    },
    #[clap(about = "Show fee estimates")]
    Fees,
    #[clap(about = "Display wallet information")]
    Info,
    #[clap(about = "Interact with ICP canister smart contracts")]
    Canister {
        #[clap(long, short, help = "Canister ID")]
        canister_id: String,
        #[clap(long, short, help = "Method name")]
        method: String,
        #[clap(long, short, help = "Arguments (JSON)")]
        args: String,
    },
    #[clap(about = "Swap ICP to another coin")]
    Swap {
        #[clap(long, short, help = "From principal")]
        from: String,
        #[clap(long, short, help = "Recipient address")]
        to_address: String,
        #[clap(long, short, help = "Amount to swap")]
        amount: u64,
        #[clap(long, short, value_enum, help = "Target coin")]
        coin: CliCoin,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum CoinType {
    #[clap(about = "Bitcoin wallet")]
    BTC,
    #[clap(about = "Monero wallet")]
    XMR,
    #[clap(about = "Solana wallet")]
    SOL,
    #[clap(about = "Ethereum wallet")]
    ETH,
    #[clap(about = "Hedera wallet")]
    HBAR,
    #[clap(about = "Internet Computer wallet")]
    ICP {
        #[clap(long, short, help = "Principal ID (optional)")]
        principal: Option<String>,
        #[clap(long, short, help = "Subaccount ID (optional)")]
        subaccount: Option<String>,
    },
}

#[derive(ValueEnum, Debug, Clone)]
pub enum CliCoin {
    Bitcoin,
    Monero,
    Solana,
    Ethereum,
    Hedera,
}

impl CliOptions {
    pub fn network_type(&self) -> HDNetworkType {
        match self.network.as_deref() {
            Some("testnet") => HDNetworkType::TestNet,
            _ => HDNetworkType::MainNet,
        }
    }

    pub fn mnemonic_type(&self) -> Result<u32> {
        let word_count = self.specified_num_words.unwrap_or(12);
        match word_count {
            12 | 15 | 18 | 21 | 24 => Ok(word_count),
            _ => Err(anyhow!("Invalid word count: {}. Choose 12, 15, 18, 21, or 24", word_count)),
        }
    }

    pub fn language(&self) -> Result<String> {
        Ok(self.language.clone().unwrap_or("english".to_string()))
    }

    pub async fn handle_command(&self, wallet: &mut WalletDIcpApi) -> Result<CliResponse> {
        let command = self.command.as_ref().unwrap_or(&Command::Info);
        match command {
            Command::GenerateKey => {
                let principal = wallet.create_wallet()?;
                println!("Generated key: {}", principal);
                Ok(CliResponse::Continue)
            }
            Command::InitWallet { coin } => {
                match coin {
                    CoinType::BTC => println!("BTC wallet initialization not implemented"),
                    CoinType::XMR => println!("Monero wallet initialization not implemented"),
                    CoinType::SOL => println!("Solana wallet initialization not implemented"),
                    CoinType::ETH => println!("Ethereum wallet initialization not implemented"),
                    CoinType::HBAR => println!("Hedera wallet initialization not implemented"),
                    CoinType::ICP { principal, subaccount } => {
                        println!("ICP wallet initialized (principal: {:?}, subaccount: {:?})", 
principal, subaccount);
                        Ok(CliResponse::Continue)
                    }
                }
                Ok(CliResponse::Continue)
            }
            Command::Address => {
                let address = wallet.generate_address().await?;
                println!("Address: {}", address);
                Ok(CliResponse::Continue)
            }
            Command::Balance => {
                let address = wallet.generate_address().await?;
                let balance = wallet.balance(&address).await?;
                println!("Balance: {} ICP", balance);
                Ok(CliResponse::Continue)
            }
            Command::Transfer { amount, to } => {
                let from = wallet.generate_address().await?;
                wallet.transfer(&from, to, (*amount as u64).max(1)).await?;
                println!("Transferred {} ICP to {}", amount, to);
                Ok(CliResponse::Continue)
            }
            Command::Transactions => {
                let address = wallet.generate_address().await?;
                let txs = wallet.transaction_history(&address).await?;
                println!("Transactions: {:?}", txs);
                Ok(CliResponse::Continue)
            }
            Command::TransactionDetails { hash } => {
                println!("Transaction details for {} (stubbed)", hash);
                Ok(CliResponse::Continue)
            }
            Command::Fees => {
                println!("Fee estimation: 0.0001 ICP (stubbed)");
                Ok(CliResponse::Continue)
            }
            Command::Info => {
                println!("WalletD ICP CLI: Stubbed wallet info");
                Ok(CliResponse::Continue)
            }
            Command::Canister { canister_id, method, args } => {
                let result: u64 = wallet.call_canister(Principal::from_text(canister_id)?, method, 
args).await?;
                println!("Canister call result: BlockIndex {}", result);
                Ok(CliResponse::Continue)
            }
            Command::Swap { from, to_address, amount, coin } => {
                let coin = match coin {
                    CliCoin::Bitcoin => Coin::Bitcoin,
                    CliCoin::Monero => Coin::Monero,
                    CliCoin::Solana => Coin::Solana,
                    CliCoin::Ethereum => Coin::Ethereum,
                    CliCoin::Hedera => Coin::Hedera,
                };
                let from_principal = Principal::from_text(from)?;
                wallet.swap_icp_to_coin(from_principal, to_address, amount, coin).await?;
                println!("Swapped {} ICP to {} address {}", amount, coin_name(&coin), to_address);
                Ok(CliResponse::Continue)
            }
        }
    }

    pub async fn prompt_choice(wallet: &mut WalletDIcpApi) -> Result<CliResponse> {
        use std::io::{stdin, stdout, Write};
        println!("Choose action for ICP wallet:");
        let address = wallet.generate_address().await?;
        let balance = wallet.balance(&address).await?;
        println!("Address: {}", address);
        println!("Balance: {} ICP", balance);
        print!("Options: [C]ontinue, [S]wap coin, [E]xit: ");
        stdout().flush()?;
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        match input.trim().to_uppercase().as_str() {
            "C" => Ok(CliResponse::Continue),
            "S" => Ok(CliResponse::Swap),
            "E" => Ok(CliResponse::Exit),
            _ => {
                println!("Invalid choice. Defaulting to Continue.");
                Ok(CliResponse::Continue)
            }
        }
    }

    pub fn specify_cryptocoin() -> Result<String> {
        use std::io::{stdin, stdout, Write};
        print!("Specify cryptocurrency (BTC/XMR/SOL/ETH/HBAR/ICP): ");
        stdout().flush()?;
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        let coin = input.trim().to_uppercase();
        match coin.as_str() {
            "BTC" | "XMR" | "SOL" | "ETH" | "HBAR" | "ICP" => Ok(coin),
            _ => Err(anyhow!("Invalid input. Please enter BTC, XMR, SOL, ETH, HBAR, or ICP")),
        }
    }
}

fn coin_name(coin: &Coin) -> &'static str {
    match coin {
        Coin::Bitcoin => "BTC",
        Coin::Monero => "XMR",
        Coin::Solana => "SOL",
        Coin::Ethereum => "ETH",
        Coin::Hedera => "HBAR",
    }
}
