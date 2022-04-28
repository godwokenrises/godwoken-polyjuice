# Comparison with EVM

Polyjuice aims at 100% EVM compatibility as a goal, meaning we plan to support all smart contracts supported by the latest Ethereum hardfork version. But in the current version, something is incompatible with EVM.

## EVM revision
The maximum EVM revision supported is `EVMC_BERLIN`.

## pCKB

[pCKB](https://github.com/nervosnetwork/godwoken/blob/develop/docs/life_of_a_polyjuice_transaction.md#pckb) is a new concept introduced by Polyjuice.

Recall that in Ethereum, the gas of each smart contract is calculated. The transaction fee is calculated then by multiplying gas with specified gas price. In Polyjuice, **pCKB** is used as the unit for calculating transaction fees. This means while the gas price in Ethereum is ETH/gas(which is denominated in wei, which is 1e-18 ether), in Polyjuice gas price is measured in pCKB/gas. When executing a transaction, Polyjuice will deduct transaction fee using the layer2 [sUDT](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0025-simple-udt/0025-simple-udt.md) type denoted by **pCKB**.

Note when sending a transaction to a smart contract for certain behavior, the `value` of the transaction is `pCKB`.

## All Tokens Are ERC20 Tokens

Ethereum differs in the processing of ERC20 tokens, and native ETH tokens. This is also the reason why wETH is invented. Godwoken conceals this difference:

Whether you use a native CKB or any sUDT token type, they will all be represented in Godwoken as a layer2 sUDT type. Polyjuice starts from this layer2 sUDT [contract](https://github.com/nervosnetwork/godwoken-polyjuice/blob/b9c3ad4/solidity/erc20/SudtERC20Proxy_UserDefinedDecimals.sol) and ensures that all the tokens on Godwoken are in compliance with the ERC20 standard, no matter if they are backed by a native CKB or a sUDT. This means you don't need to distinguish between native token and ERC20 tokens. All you have to deal with is the same ERC20 interface for all different tokens.

## Transaction Structure

A Polyjuice transaction is essentially just a Godwoken transaction.

When you send an Ethereum transaction, the transaction is converted to Godwoken [RawL2Transaction](https://github.com/nervosnetwork/godwoken/blob/v1.0.0-rc1/crates/types/schemas/godwoken.mol#L69-L74) type which is automatically handled by [Godwoken Web3](https://github.com/nervosnetwork/godwoken-web3/tree/v1.0.0-rc1).

## Behavioral differences of some opcodes

| EVM Opcode | Solidity Usage | Behavior in Polyjuice | Behavior in EVM |
| - | - | - | - |
| COINBASE | `block.coinbase` | address of the block_producer | address of the current block's miner |
| GASLIMIT | `block.gaslimit` | 12,500,000 | current block's gas limit |
| DIFFICULTY | `block.difficulty` | 2,500,000,000,000,000 | current block's difficulty |

### Restriction of memory usage

Polyjuice runs EVM on ckb-vm. While EVM has no limit on memory usage (despite the limit of 1024 on stack depth for EVM), ckb-vm can use a maximum of 4MB of memory for now.
Of which, 3MB for heap space and 1MB for stack space. See more details in [here](https://github.com/nervosnetwork/riscv-newlib/blob/00c6ae3c481bc62b4ac016b3e86c508cdf2e68d2/libgloss/riscv/sys_sbrk.c#L38-L56). 
For some contracts that consume a lot of memory or that have deep call stacks, this may indicate a potential incompatibility on ckb-vm.

## Others

* Transaction context
  * `chain_id` is defined in Godwoken [RollupConfig#chain_id](https://github.com/nervosnetwork/godwoken/blob/a099f2010b212355f5504a8d464b6b70d29640a5/crates/types/schemas/godwoken.mol#L64).
  * the block difficulty is always `2500000000000000`
  * the gas limit for each block is 12500000; it is not a transaction-level limit. Any transaction can reach the gas limit
  * the size limit for contract's return data is [`25600B`](https://github.com/nervosnetwork/godwoken-scripts/blob/31293d1/c/gw_def.h#L21-L22)
  * the size limit for contract's storage is [`25600B`](https://github.com/nervosnetwork/godwoken-scripts/blob/31293d1/c/gw_def.h#L21-L22)


* `transaction.to` MUST be a Contract Address

  Value (pCKB) transfer from EOA to EOA directly is not supported.
  > Workaround: pCKB (CKB) is represented as an ERC20 token on layer2, it could be transfer through the [sUDT_ERC20_Proxy](https://github.com/nervosnetwork/godwoken-polyjuice/blob/3f1ad5b/solidity/erc20/README.md) contract's `transfer function`.
* The `transfer value` can not exceed uint128:MAX

* Pre-compiled contract
  * `bn256_pairing` is not supported yet，due to too high cycle cost (WIP)
  * [addition pre-compiled contracts](Addition-Features.md)
