## Comparison with EVM
Polyjuice aims at 100% EVM compatibility as a goal, meaning we plan to support all smart contracts supported by the latest Ethereum hardfork version. But in the current version, something is incompatible with EVM.

### pETH
**pETH** is a new concept introduced by Polyjuice. 

Recall that in Ethereum, the gas of each smart contract is calculated. The transaction fee is calculated then by multiplying gas with specified gas price. In Polyjuice, **pETH** is used as the unit for calculating transaction fees. This means while the gas price in Ethereum is ETH/gas(which is denominated in wei, which is 1e-18 ether), in Polyjuice gas price is measured in pETH/gas. When executing a transaction, Polyjuice will deduct transaction fees using tokens in the layer 2 sUDT type denoted by **pETH**.

Note in Ethereum, one can also send some ETH to a smart contract for certain behavior. In Polyjuice, this feature is also performed by sending pETH.

### Account Abstraction
Polyjuice only provides [contract accounts](https://ethereum.org/en/glossary/#contract-account). Godwoken's user accounts are leveraged to act as [EoAs](https://ethereum.org/en/glossary/#eoa).

#### Different Address Type: 
* All eth_address(EoA/contract) format are `short_godwoken_account_script_hash`, which is the 20 bytes prefix of Godwoken account script hash
* Creating a contract account returns `short_godwoken_account_script_hash`

When you pass some [address-type](https://docs.soliditylang.org/en/v0.8.9/types.html#address) parameters to call smart-contract, the `address` converting must be done first, vice versa for the return `address` value. [Polyjuice-Provider](https://github.com/nervosnetwork/polyjuice-provider) has been designed to handle these conversion tasks. It converts `address` type converting according to your contract's ABI. 

### Transaction Structure
A Polyjuice transaction is essentially just a godwoken transaction, since Polyjuice is the main [backend of Godwoken](https://github.com/nervosnetwork/godwoken/blob/master/docs/life_of_a_godwoken_transaction.md#backend) for state computation.

When you send an ethereum transaction to Godwoken-Polyjuice, the data structure of this very transaction needs to be converted to godwoken [RawL2Transaction](https://github.com/nervosnetwork/godwoken/blob/9a3d92/crates/types/schemas/godwoken.mol#L56-L61) type. Also [Polyjuice-Provider](https://github.com/nervosnetwork/polyjuice-provider) has been designed to handle it.

### Others
* The `transfer value` can not exceed uint128:MAX
* transaction context
  - chain_id is creator_account_id
  - block gas limit is `12500000`, and is not block level limit, every transaction can reach the limit
  - block difficulty is `2500000000000000`
* pre-compiled contract
  - `bn256_pairing` is not supported yet，due to too high cycle cost (WIP) 
