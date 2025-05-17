use walletd_icp_cli::{CliOptions, CliResponse, icp_overview, display_message, cli_options::{Command, 
CoinType}};
use clap::Parser;
use walletd_icp_api::WalletDIcpApi;

#[tokio::main]
async fn main() {
    use cfonts::{say, Options, Align, Colors, Fonts, BgColors, Env};

    say(Options {
        text: String::from("WalletD ICP CLI"),
        font: Fonts::FontBlock,
        colors: vec![Colors::System],
        background: BgColors::Transparent,
        align: Align::Left,
        letter_spacing: 1,
        line_height: 1,
        spaceless: false,
        max_length: 0,
        env: Env::Cli,
        ..Options::default()
    });

    let cli_options = CliOptions::parse();

    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .without_timestamps()
        .init()
        .unwrap();

    let mut wallet = WalletDIcpApi::new_test().expect("Failed to initialize WalletDIcpApi");

    if let Some(command) = &cli_options.command {
        let result = match command {
            Command::InitWallet { coin } => match coin {
                CoinType::BTC => {
                    println!("BTC wallet initialization not supported");
                    Ok(CliResponse::Continue)
                }
                CoinType::XMR => {
                    println!("Monero wallet initialization not supported");
                    Ok(CliResponse::Continue)
                }
                CoinType::SOL => {
                    println!("Solana wallet initialization not supported");
                    Ok(CliResponse::Continue)
                }
                CoinType::ETH => {
                    println!("Ethereum wallet initialization not supported");
                    Ok(CliResponse::Continue)
                }
                CoinType::HBAR => {
                    println!("Hedera wallet initialization not supported");
                    Ok(CliResponse::Continue)
                }
                CoinType::ICP { .. } => cli_options.handle_command(&mut wallet).await,
            },
            _ => cli_options.handle_command(&mut wallet).await,
        };
        if let Err(e) = result {
            println!("Command failed: {}", e);
        }
    } else {
        let mut coin_type = CliOptions::specify_cryptocoin().expect("Failed to specify coin");
        loop {
            let continue_session = match coin_type.as_str() {
                "BTC" => {
                    println!("BTC not supported in this build");
                    Ok(CliResponse::Continue)
                }
                "XMR" => {
                    println!("Monero not supported in this build");
                    Ok(CliResponse::Continue)
                }
                "SOL" => {
                    println!("Solana not supported in this build");
                    Ok(CliResponse::Continue)
                }
                "ETH" => {
                    println!("Ethereum not supported in this build");
                    Ok(CliResponse::Continue)
                }
                "HBAR" => {
                    println!("Hedera not supported in this build");
                    Ok(CliResponse::Continue)
                }
                "ICP" => {
                    let address = wallet.generate_address().await.unwrap_or("unknown".to_string());
                    let overview = icp_overview(&wallet, &address).await.unwrap_or("Error fetching 
overview".to_string());
                    display_message(&overview);
                    CliOptions::prompt_choice(&mut wallet).await
                }
                _ => {
                    println!("Invalid coin type");
                    Ok(CliResponse::Continue)
                }
            };
            match continue_session {
                Ok(continue_session) => match continue_session {
                    CliResponse::Exit => break,
                    CliResponse::Swap => {
                        coin_type = CliOptions::specify_cryptocoin().expect("Failed to specify 
coin");
                    }
                    CliResponse::Continue => continue,
                }
                Err(e) => println!("Error: {}", e),
            }
        }
    }
}
