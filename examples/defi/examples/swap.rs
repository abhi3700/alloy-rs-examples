use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use std::env;

// sol! {
//     interface IERC20 {
//         function approve(address spender, uint256 amount) external returns (bool);
//     }

//     interface IUniswapV3Factory {
//         function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);
//     }

//     interface IUniswapV3Router {
//         function exactInputSingle(
//             tuple(address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)
//         ) external payable returns (uint256 amountOut);
//     }

//     interface IQuoter {
//         function quoteExactInputSingle(
//             address tokenIn,
//             address tokenOut,
//             uint24 fee,
//             uint256 amountIn,
//             uint160 sqrtPriceLimitX96
//         ) external returns (uint256 amountOut);
//     }
// }

// TODO: add the corresponding artifacts.
// Codegen from artifact.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IUniswapV3Router,
    "examples/artifacts/IUniswapV3Router.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IUniswapV3Factory,
    "examples/artifacts/IUniswapV3Factory.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "examples/artifacts/IERC20.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IQuoter,
    "examples/artifacts/IQuoter.json"
);

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();
    let rpc_url = env::var("RPC_URL")?;
    let private_key = env::var("PRIVATE_KEY")?; // must start with '0x'

    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new().wallet(signer).connect_http(rpc_url.parse()?);

    // Contracts
    let usdt = IERC20::new("0xdAC17F958D2ee523a2206206994597C13D831ec7".parse()?, signer.clone());
    let usdc_addr: Address = "0xA0b86991C6218b36c1D19D4a2e9Eb0cE3606EB48".parse()?;
    let router = IUniswapV3Router::new(
        "0xE592427A0AEce92De3Edee1F18E0157C05861564".parse()?,
        signer.clone(),
    );
    let quoter =
        IQuoter::new("0x61fFE014bA17989E743c5F6cB21bF9697530B21e".parse()?, provider.clone());
    let factory = IUniswapV3Factory::new(
        "0x1F98431c8aD98523631AE4a59f267346ea31F984".parse()?,
        provider.clone(),
    );

    let token_a = usdt.address();
    let token_b = usdc_addr;

    // Step 1: Find pool and fee tier
    let fee_tiers = [100u32, 500, 3000];
    let mut found_pool = None;
    let mut found_fee = None;

    for &fee in &fee_tiers {
        let pool_addr = factory.getPool(token_a, token_b, fee).call().await?;
        if pool_addr != Address::ZERO {
            println!("✅ Found pool at {} with fee {} ({}%)", pool_addr, fee, fee as f64 / 1e4);
            found_pool = Some(pool_addr);
            found_fee = Some(fee);
            break;
        }
    }

    let fee = match found_fee {
        Some(fee) => fee,
        None => {
            println!("❌ No pool found for this token pair");
            return Ok(());
        }
    };

    // Step 2: Estimate output
    let amount_in = U256::from(10_000_000u64); // 10 USDT
    let estimated_out = quoter
        .quoteExactInputSingle(token_a, token_b, fee, amount_in, U256::from(0))
        .call()
        .await?;
    println!("Estimated USDC out: {}", estimated_out);

    let slippage = 1.0; // 1%
    let slippage_factor = 1.0 - (slippage / 100.0);
    let amount_out_min = (estimated_out.as_u128() as f64 * slippage_factor) as u128;
    println!("AmountOutMin (1% slippage): {}", amount_out_min);

    // Step 3: Approve Router
    let approve_tx = usdt.approve(router.address(), amount_in).send().await?.await?;
    println!("✅ Approved: {:?}", approve_tx.transaction_hash);

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();

    // Step 4: Swap
    let params = (
        token_a,
        token_b,
        fee,
        signer.address(),
        (now + 300) as u64,
        amount_in,
        U256::from(amount_out_min),
        U256::from(0),
    );

    let swap_tx = router.exactInputSingle(params).send().await?.await?;
    println!("✅ Swap complete: {:?}", swap_tx.transaction_hash);

    Ok(())
}
