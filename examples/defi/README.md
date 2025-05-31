# DeFi

## TODO

- [ ] swap token (USDT:USDC) using uniswap-v3
  - [x] add artifacts via `forge b` & additional settings.
  - [ ] Run it
- [ ] May create a lib
- [ ] arbitrage bot. Reference: [foo](../advanced/examples/uniswap_u256/ethers_profit.rs).

## Pre-requisite

Install foundry on Uniswap-v2 (Core, Periphery), Uniswap-v3 (Core, Periphery) repos

---

Inside `v3-periphery` did this:

```sh
forge init --force
```

Also, added a custom `remappings.txt` file for the imported files.

So, pushed to my account: <https://github.com/abhi3700/v3-core.git>.

---

Inside `v3-periphery` did this:

```sh
forge init --force

# install libs
forge install Uniswap/v2-core@v1.0.1 
forge install Uniswap/v3-core@v1.0.0 
forge install OpenZeppelin/openzeppelin-contracts@v3.4.2-solc-0.7
forge install Brechtpd/base64@v1.1.0
forge install Uniswap/solidity-lib@v4.0.0-alpha
```

Also, added a custom `remappings.txt` file for the imported files.

So, pushed to my account: <https://github.com/abhi3700/v3-periphery.git>.

## Artifacts

Now, you can get the artifacts from my repos.
