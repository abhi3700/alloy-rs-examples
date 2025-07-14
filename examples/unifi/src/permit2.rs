//! Example of how to transfer ERC20 tokens from one account to another using a signed permit.

use crate::permit2::{ISignatureTransfer::SignatureTransferDetails, Permit2::Permit2Instance};
use alloy::{
    dyn_abi::Eip712Domain,
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, Provider, RootProvider,
    },
    sol,
    sol_types::eip712_domain,
};
use eyre::ensure;

// Codegen from artifact.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Permit2,
    "src/artifacts/Permit2.json"
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

type CustomProvider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

/// Create the EIP712 Domain and Permit
pub async fn create_domain_permit(
    provider: CustomProvider,
    permit2_address: Address,
    payer: Address,
    token_addr: Address,
    amount: U256,
    fee: U256,
    spender: Address,
    expiration_sec: u64,
) -> eyre::Result<(Eip712Domain, PermitBatchTransferFrom)> {
    // EIP712 Domain
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: provider.get_chain_id().await?,
        verifying_contract: permit2_address,
    };

    let permit2 = Permit2::new(permit2_address, provider.clone());

    // fetch the latest nonce of (owner, token, spender)
    let nonce = find_next_unused_nonce(permit2, payer).await?.unwrap();

    // Permit
    let permit = PermitBatchTransferFrom {
        permitted: vec![
            TokenPermissions { token: token_addr, amount },
            TokenPermissions { token: token_addr, amount: fee },
        ],
        spender,
        nonce: U256::from(nonce),
        deadline: {
            let expiration =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
                    + expiration_sec; // valid for 15 minutes
            U256::from(expiration)
        },
    };

    Ok((domain, permit))
}

/// Finds the next unused nonce from the nonceBitmap
///
/// # Arguments
/// * `permit2` - Permit2 Contract
/// * `user` - The address whose nonceBitmap to inspect
///
/// # Returns
/// * `Option<u256>` - The first unused nonce, or None if all are taken
pub async fn find_next_unused_nonce(
    permit2: Permit2Instance<CustomProvider>,
    user: Address,
) -> eyre::Result<Option<U256>> {
    let max_words = U256::from(1000);
    let mut word_pos = U256::ZERO;
    while word_pos < max_words {
        let bitmap: U256 = permit2.nonceBitmap(user, word_pos).call().await?;

        for bit_pos in 0..256 {
            let bit = U256::from(1) << bit_pos;
            if bitmap & bit == U256::ZERO {
                let nonce = (word_pos << 8) | U256::from(bit_pos);
                return Ok(Some(nonce));
            }
        }

        word_pos += U256::ONE;
    }

    Ok(None) // No unused nonce found
}

/// Create transfer details
pub fn create_transfer_details(
    tos: &[Address],
    amounts: &[U256],
) -> eyre::Result<Vec<SignatureTransferDetails>> {
    ensure!(tos.len().eq(&amounts.len()), "tos != amounts for permitTransferFrom");

    Ok(tos
        .iter()
        .zip(amounts.iter())
        .into_iter()
        .map(|(&to, &amount)| SignatureTransferDetails { to, requestedAmount: amount })
        .collect::<Vec<_>>())
}
