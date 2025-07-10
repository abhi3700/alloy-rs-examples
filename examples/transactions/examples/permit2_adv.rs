//! Example of how to transfer ERC20 tokens from one account to another using a signed permit.

use crate::ISignatureTransfer::SignatureTransferDetails;
use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, Signer},
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

    struct PermitBatchTransferFrom {
        TokenPermissions[] permitted;
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

impl From<PermitBatchTransferFrom> for ISignatureTransfer::PermitBatchTransferFrom {
    fn from(val: PermitBatchTransferFrom) -> Self {
        Self {
            permitted: val
                .permitted
                .into_iter()
                .map(|p| ISignatureTransfer::TokenPermissions { token: p.token, amount: p.amount })
                .collect(),
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
    // Instead, we use a custom mnemonic generated via:
    // `anvil --mnemonic-random 12 --fork-url $RPC_URL`
    let anvil = Anvil::new()
        .fork(rpc_url)
        .mnemonic("tunnel tiger ankle life lift risk wash material promote damp sadness middle")
        .try_spawn()?;

    // Set up signers from the first 3 default Anvil accounts (Alice, Bob, Charlie).
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

    // Alice approves the Permit2 contract
    let tx_hash = token
        .approve(*permit2.address(), U256::MAX)
        .from(alice.address())
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent approval by Alice: {tx_hash}");

    // Create the EIP712 Domain and Permit
    let amount = U256::from(100);
    let fee = U256::from(1);
    let total_amount = amount + fee;
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: provider.get_chain_id().await?,
        verifying_contract: *permit2.address(),
    };

    // fetch the latest nonce of (owner, token, spender) i.e. (alice, token, charlie).
    let nonce =
        permit2.allowance(alice.address(), *token.address(), charlie.address()).call().await?.nonce;

    let permit = PermitBatchTransferFrom {
        permitted: vec![
            TokenPermissions { token: *token.address(), amount },
            TokenPermissions { token: *token.address(), amount: fee },
        ],
        spender: charlie.address(),
        nonce: U256::from(nonce),
        deadline: {
            let expiration =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + 900; // valid for 15 minutes
            U256::from(expiration)
        },
    };

    // Alice signs the Permit once.
    let signature: Bytes = alice.sign_typed_data(&permit, &domain).await?.as_bytes().into();

    // This specifies the actual transaction executed via Permit2
    // Note that `to` can be any address and does not have to match the spender
    let transfers_details = vec![
        SignatureTransferDetails { to: bob.address(), requestedAmount: amount },
        SignatureTransferDetails { to: charlie.address(), requestedAmount: fee },
    ];

    let tx_hash = permit2
        .permitTransferFrom_1(
            permit.clone().into(),
            transfers_details,
            alice.address(),
            signature.clone(),
        )
        .from(charlie.address()) // the spender of the permit must be the msg.sender
        .send()
        .await?
        .watch()
        .await?;
    println!("Sent permit transfer to Bob & Charlie: {tx_hash}");

    // Register the balances of Alice and Bob after the transfer.
    let alice_after_balance = token.balanceOf(alice.address()).call().await?;
    let bob_after_balance = token.balanceOf(bob.address()).call().await?;
    let charlie_after_balance = token.balanceOf(charlie.address()).call().await?;

    // Check the balances of Alice and Bob after the transfer.
    assert_eq!(alice_before_balance - alice_after_balance, total_amount);
    assert_eq!(bob_after_balance - bob_before_balance, amount);
    assert_eq!(charlie_after_balance - charlie_before_balance, fee);

    Ok(())
}
