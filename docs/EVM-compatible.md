# Comparison with EVM

Polyjuice aims at 100% EVM compatibility as a goal, meaning we plan to support all smart contracts supported by the latest Ethereum hardfork version. But in the current version, something is incompatible with EVM.

## EVM revision
The maximum EVM revision supported is `EVMC_BERLIN`.
- [ ] support EVMC_LONDON
- [ ] support EVMC_SHANGHAI

## pETH

**pETH** is a new concept introduced by Polyjuice.

Recall that in Ethereum, the gas of each smart contract is calculated. The transaction fee is calculated then by multiplying gas with specified gas price. In Polyjuice, **pETH** is used as the unit for calculating transaction fees. This means while the gas price in Ethereum is ETH/gas(which is denominated in wei, which is 1e-18 ether), in Polyjuice gas price is measured in pETH/gas. When executing a transaction, Polyjuice will deduct transaction fees using tokens in the layer2 [sUDT](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md) type denoted by **pETH**.

Note in Ethereum, one can also send some ETH to a smart contract for certain behavior. In Polyjuice, this feature is also performed by sending pETH.

## Account Abstraction

Polyjuice only provides [contract accounts](https://ethereum.org/en/glossary/#contract-account). Godwoken's user accounts are leveraged to act as [EOAs](https://ethereum.org/en/glossary/#eoa).

## All Tokens Are ERC20 Tokens

Ethereum differs in the processing of ERC20 tokens, and native ETH tokens. This is also the reason why wETH is invented. Godwoken conceals this difference:

Whether you use a native CKB or any sUDT token type, they will all be represented in Godwoken as a layer2 sUDT type. Polyjuice starts from this layer2 sUDT [contract](https://github.com/nervosnetwork/godwoken-polyjuice/blob/b9c3ad4/solidity/erc20/SudtERC20Proxy_UserDefinedDecimals.sol) and ensures that all the tokens on Godwoken are in compliance with the ERC20 standard, no matter if they are backed by a native CKB or a sUDT. This means you don't need to distinguish between native token and ERC20 tokens. All you have to deal with is the same ERC20 interface for all different tokens.

## Transaction Structure

A Polyjuice transaction is essentially just a Godwoken transaction.

When you send an Ethereum transaction, the transaction is converted to Godwoken [RawL2Transaction](https://github.com/nervosnetwork/godwoken/blob/9a3d92/crates/types/schemas/godwoken.mol#L56-L61) type which is automatically handled by [Godwoken Web3](https://github.com/nervosnetwork/godwoken-web3/tree/6e78293).

## Behavioral differences of some opcodes

| EVM Opcode | Solidity Usage | Behavior in Polyjuice | Behavior in EVM |
| - | - | - | - |
| COINBASE | `block.coinbase` | address of the block_producer | address of the current block's miner |
| GASLIMIT | `block.gaslimit` | 12,500,000 | current block's gas limit |
| DIFFICULTY | `block.difficulty` | 2,500,000,000,000,000 | current block's difficulty |

## Others

* Transaction context
  * `chain_id` consists up of two parts: [**compatible_chain_id(u32) | [creator_account_id]()(u32)**]
    - `compatible_chain_id` is defined in Godwoken [RollupConfig](https://github.com/nervosnetwork/godwoken/blob/acc6614/crates/types/schemas/godwoken.mol#L64).
    - `creator_account` is known as [the root account of Polyjuice](https://github.com/nervosnetwork/godwoken/blob/5735d8f/docs/life_of_a_polyjuice_transaction.md#root-account--deployment).
  * block gas limit is `12500000`, and is not block level limit, every transaction can reach the limit
  * block difficulty is always `2500000000000000`

* Value (pETH) transfer from EOA to EOA directly is not supported.
  > Workaround: pETH (CKB) is represented as an ERC 20 token on layer2, it could be transfer through the [sUDT_ERC20_Proxy](https://github.com/nervosnetwork/godwoken-polyjuice/blob/3f1ad5b/solidity/erc20/README.md) contract's `transfer function`.
* The `transfer value` can not exceed uint128:MAX

* Pre-compiled contract
  * `bn256_pairing` is not supported yet，due to too high cycle cost (WIP)
  * [addition pre-compiled contracts](Addition-Features.md)
