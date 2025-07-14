//! Example of how to transfer ERC20 tokens from one account to another using a signed permit.
//!
//! Using Allowance Transfer approach. NOTE:  Usage:
//! 1. token.approve by Alice
//! 2. permit2.permit by Bob
//! 3. permit2.transferFrom by Bob
//!
//! Total 3 txs.
//!
//! But, next time onwards, just step-3 is needed if the permit is still valid.
//! Just ensure the caller is same i.e matches with what is set in Permit.
//!
//! ## Usage
//! - For recurring payemnts.

use crate::IAllowanceTransfer::{PermitDetails, PermitSingle};
use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{aliases::U48, Address, U160, U256},
    providers::{Provider, ProviderBuilder},
    signers::{
        local::{
            coins_bip39::{English, Mnemonic},
            PrivateKeySigner,
        },
        Signer,
    },
    sol,
    sol_types::eip712_domain,
};
use eyre::Result;
use std::str::FromStr;

// Codegen from artifact.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20Example,
    "examples/artifacts/ERC20Example.json"
);

// Codegen from artifact.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Permit2,
    "examples/artifacts/Permit2.json"
);

// The permit stuct that has to be signed is different from the contract input struct
// even though they have the same name.
// Also note that the EIP712 hash of this struct is sensitive to the order of the fields.
sol! {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        address spender;
        uint256 nonce;
        uint256 deadline;
    }
}

impl From<PermitTransferFrom> for ISignatureTransfer::PermitTransferFrom {
    fn from(val: PermitTransferFrom) -> Self {
        Self {
            permitted: ISignatureTransfer::TokenPermissions {
                token: val.permitted.token,
                amount: val.permitted.amount,
            },
            nonce: val.nonce,
            deadline: val.deadline,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Spin up a local Anvil node.
    // Ensure `anvil` is available in $PATH.
    let rpc_url = "https://reth-ethereum.ithaca.xyz/rpc";
    // NOTE: ⚠️ Due to changes in EIP-7702 (see: https://getfoundry.sh/anvil/overview/#eip-7702-and-default-accounts),
    // the default mnemonic cannot be used for signature-based testing.
    let mnemonic = generate_mnemonic()?;
    let anvil = Anvil::new().fork(rpc_url).mnemonic(mnemonic).try_spawn()?;

    // Set up signers from the first two default Anvil accounts (Alice, Bob).
    let alice: PrivateKeySigner = anvil.keys()[7].clone().into();
    let bob: PrivateKeySigner = anvil.keys()[8].clone().into();
    let charlie: PrivateKeySigner = anvil.keys()[9].clone().into();

    // We can manage multiple signers with the same wallet
    let mut wallet = EthereumWallet::new(alice.clone());
    wallet.register_signer(bob.clone());
    wallet.register_signer(charlie.clone());

    // Create a provider with both signers pointing to anvil
    let rpc_url = anvil.endpoint_url();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Deploy the `ERC20Example` contract.
    let token = ERC20Example::deploy(provider.clone()).await?;

    // Register the balances of Alice and Bob before the transfer.
    let alice_before_balance = token.balanceOf(alice.address()).call().await?;
    let bob_before_balance = token.balanceOf(bob.address()).call().await?;
    let charlie_before_balance = token.balanceOf(charlie.address()).call().await?;

    // Permit2 mainnet address
    let address = Address::from_str("0x000000000022D473030F116dDEE9F6B43aC78BA3")?;
    let permit2 = Permit2::new(address, provider.clone());

    // ===== 1. approve ====

    // Alice approves the Permit2 contract
    let tx_hash = token
        .approve(*permit2.address(), U256::MAX)
        .from(alice.address())
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent approval: {tx_hash}");

    let expiration =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + 900; // valid for 15 minutes

    let amount1 = U256::from(100);
    let amount2 = U256::from(150);
    // Create the EIP712 Domain
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: provider.get_chain_id().await?,
        verifying_contract: *permit2.address(),
    };

    // ===== 2. permit ====

    // Create the Permit
    let permit = PermitSingle {
        details: PermitDetails {
            token: *token.address(),
            amount: U160::from(amount1 + amount2),
            expiration: U48::from(expiration),
            nonce: U48::from(0),
        },
        spender: bob.address(),
        sigDeadline: U256::from(expiration),
    };

    // Alice signs the Permit
    let signature: alloy::primitives::Bytes =
        alice.sign_typed_data(&permit, &domain).await?.as_bytes().into();

    let tx_hash = permit2
        .permit_1(alice.address(), permit.into(), signature.clone())
        .from(bob.address())
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent permit tx: {}", tx_hash);

    // spender must be msg.sender
    let allowance =
        permit2.allowance(alice.address(), *token.address(), bob.address()).call().await?;
    println!("permit allowance: {}", allowance.amount);
    println!("permit expiration: {}", allowance.expiration);

    // === 3. transferFrom ==

    let tx_hash = permit2
        .transferFrom_1(alice.address(), bob.address(), U160::from(amount1), *token.address())
        .from(bob.address()) // the spender of the permit must be the msg.sender
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent permit transfer: {tx_hash}");

    // === 4. transferFrom ==

    let tx_hash = permit2
        .transferFrom_1(alice.address(), charlie.address(), U160::from(amount2), *token.address())
        .from(bob.address()) // the spender of the permit must be the msg.sender
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent permit transfer: {tx_hash}");

    // Register the balances of Alice and Bob after the transfer.
    let alice_after_balance = token.balanceOf(alice.address()).call().await?;
    let bob_after_balance = token.balanceOf(bob.address()).call().await?;
    let charlie_after_balance = token.balanceOf(charlie.address()).call().await?;

    // Check the balances of Alice and Bob after the transfer.
    assert_eq!(alice_before_balance - alice_after_balance, amount1 + amount2);
    assert_eq!(bob_after_balance - bob_before_balance, amount1);
    assert_eq!(charlie_after_balance - charlie_before_balance, amount2);

    Ok(())
}

fn generate_mnemonic() -> Result<String> {
    let mut rng = rand::thread_rng();
    let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, 12)?.to_phrase();
    Ok(mnemonic)
}
