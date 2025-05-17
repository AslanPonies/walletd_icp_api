use anyhow::Result;
use walletd_icp_api::WalletDIcpApi;

pub async fn icp_overview(wallet: &WalletDIcpApi, address: &str) -> Result<String> {
    let mut overview = String::new();
    let balance = wallet.balance(address).await?;
    std::fmt::write(&mut overview, format_args!("Balance (ICP): {}\n", balance))?;
    std::fmt::write(&mut overview, format_args!("Address: {}\n", address))?;
    Ok(overview)
}

pub fn display_message(msg: &str) {
    println!("{}", msg);
}
