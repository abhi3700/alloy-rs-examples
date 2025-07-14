//! Example of how to transfer ERC20 tokens from one account to another using a signed permit.

use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{Address, Bytes, U256},
    providers::ProviderBuilder,
    signers::{
        local::{
            coins_bip39::{English, Mnemonic},
            PrivateKeySigner,
        },
        Signer,
    },
    sol,
};
use eyre::Result;
use std::str::FromStr;
use unifi::bundleup::{create_domain_permit, create_transfer_details, BundlePayV2};

// Codegen from artifact.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20Example,
    "examples/artifacts/ERC20Example.json"
);

#[tokio::main]
async fn main() -> Result<()> {
    // Spin up a local Anvil node.
    // Ensure `anvil` is available in $PATH.
    // let rpc_url = "https://reth-ethereum.ithaca.xyz/rpc";
    let rpc_url = "wss://ethereum-sepolia-rpc.publicnode.com";
    // NOTE: ⚠️ Due to changes in EIP-7702 (see: https://getfoundry.sh/anvil/overview/#eip-7702-and-default-accounts),
    // the default mnemonic cannot be used for signature-based testing.
    let mnemonic = generate_mnemonic()?;
    let anvil = Anvil::new().fork(rpc_url).mnemonic(mnemonic).try_spawn()?;

    // Set up signers from the first 3 default Anvil accounts (Alice, Bob, Charlie).
    let alice: PrivateKeySigner = anvil.keys()[7].clone().into();
    let bob: PrivateKeySigner = anvil.keys()[8].clone().into();

    dotenvy::dotenv().ok();
    let admin_address = std::env::var("UNIFI_ADMIN").expect("UNIFI_ADMIN not defined");
    let admin_address = admin_address.parse()?;
    let relayer1_sk_str = std::env::var("RELAYER1_SK").expect("RELAYER1_SK not defined");
    let relayer1_sk: PrivateKeySigner = relayer1_sk_str.parse()?;
    let relayer1_addr = relayer1_sk.address();
    // let relayer_wallet = EthereumWallet::new(&relayer1_sk.clone());

    // We can manage multiple signers with the same wallet
    let mut wallet = EthereumWallet::new(alice.clone());
    wallet.register_signer(relayer1_sk);

    // Create a provider with both signers pointing to anvil
    let rpc_url = anvil.endpoint_url();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Deploy the `ERC20Example` contract.
    let token = ERC20Example::deploy(provider.clone()).await?;

    // Register the balances of Alice and Bob before the transfer.
    let alice_before_balance = token.balanceOf(alice.address()).call().await?;
    let bob_before_balance = token.balanceOf(bob.address()).call().await?;
    let admin_before_balance = token.balanceOf(admin_address).call().await?;

    // Permit2 mainnet address
    let permit2_address = Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")?;

    // Alice approves the Permit2 contract
    let tx_hash = token
        .approve(permit2_address, U256::MAX)
        .from(alice.address())
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent approval by Alice: {tx_hash}");

    // BundlePayV2
    let bpay_address = Address::from_str("0x3D04219ff10b18B8a657EC1f788796CE5FEdc293")?;
    let bundle_pay = BundlePayV2::new(bpay_address, provider.clone());

    let amount = U256::from(100);
    let fee = U256::from(1);

    // Create the EIP712 Domain and Permit
    let (domain, permit) = create_domain_permit(
        provider,
        permit2_address,
        alice.address(),
        *token.address(),
        amount,
        fee,
        bpay_address,
        // valid for 15 minutes
        900,
    )
    .await?;

    // Alice signs the Permit once.
    let signature: Bytes = alice.sign_typed_data(&permit, &domain).await?.as_bytes().into();

    // This specifies the actual transaction executed via Permit2
    // Note that `to` can be any address and does not have to match the spender
    let transfers_details =
        create_transfer_details(&[bob.address(), admin_address], &[amount, fee])?;

    let tx_hash = bundle_pay
        .singlePaymentSSSTSRPermit(1, alice.address(), permit.into(), transfers_details, signature)
        .from(relayer1_addr) // the spender of the permit must be the msg.sender (caller)
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent permit transfer to Bob & Admin: {tx_hash}");

    // Register the balances of Alice and Bob after the transfer.
    let alice_after_balance = token.balanceOf(alice.address()).call().await?;
    let bob_after_balance = token.balanceOf(bob.address()).call().await?;
    let admin_after_balance = token.balanceOf(admin_address).call().await?;

    // Check the balances of Alice and Bob after the transfer.
    assert_eq!(alice_before_balance - alice_after_balance, amount + fee);
    assert_eq!(bob_after_balance - bob_before_balance, amount);
    assert_eq!(admin_after_balance - admin_before_balance, fee);

    Ok(())
}

fn generate_mnemonic() -> Result<String> {
    let mut rng = rand::thread_rng();
    let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, 12)?.to_phrase();
    Ok(mnemonic)
}
