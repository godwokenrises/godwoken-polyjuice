
# Godwoken Polyjuice
An Ethereum compatible backend for [Godwoken](https://github.com/nervosnetwork/godwoken) (a generic optimistic rollup framework). It includes [generator](./c/generator.c) and [validator](./c/validator.c) implementations.

Polyjuice provides an [Ethereum](https://ethereum.org/en/) compatible layer on [Nervos CKB](https://github.com/nervosnetwork/ckb). It leverages account model as well as scalability provided by [Godwoken](https://github.com/nervosnetwork/godwoken/blob/develop/docs/life_of_a_godwoken_transaction.md), then integrates [evmone](https://github.com/ethereum/evmone) as an EVM engine for running Ethereum smart contracts.

Polyjuice aims at 100% EVM compatibility as a goal, meaning we plan to support all smart contracts supported by the latest Ethereum hardfork version. See [EVM-compatible.md](docs/EVM-compatible.md) and [Addition-Features.md](docs/Addition-Features.md) for more details.

## Features
- [x] All [Ethereum Virtual Machine Opcodes](https://ethervm.io/)
- [x] Value transfer
- [ ] pre-compiled contracts
  + [x] ecrecover
  + [x] sha256hash
  + [x] ripemd160hash
  + [x] dataCopy
  + [x] bigModExp
  + [x] bn256AddIstanbul
  + [x] bn256ScalarMulIstanbul
  + [ ] bn256PairingIstanbul (performance issue)
  + [x] blake2F


## Data Structures

### Polyjuice arguments
```
header     : [u8; 8]  (header[0]    = 0xff, 
                       header[1]    = 0xff, 
                       header[2]    = 0xff, 
                       header[3..7] = "POLY"
                       header[7]    = call_kind { 0: CALL, 3: CREATE })
gas_limit  : u64      (little endian)
gas_price  : u128     (little endian)
value      : u128     (little endian)
input_size : u32      (little endian)
input_data : [u8; input_size]   (input data)
```

Every Polyjuice argument fields must been serialized one by one and put into Godwoken [`RawL2Transaction.args`][rawl2tx-args] for Polyjuice to read. If the `input_data` have 56 bytes, then the serialized data size is `8 + 8 + 16 + 16 + 4 + 56 = 108` bytes.


### Creator account script
```
code_hash: Polyjuice_validator_type_script_hash
hash_type: type
args:
    rollup_type_hash : [u8; 32]
    sudt_id          : u32          (little endian, the token id)
    eth_addr_reg_id  : u32          (little endian, the ETH_Address_Registry Contract id)
```

Polyjuice creator account is a Godwoken account for creating Polyjuice contract account. This account can only be created by [meta contract][meta-contract], and the account id is used as the chain id in Polyjuice. The `sudt_id` field in script args is the sUDT token current Polyjuice instance bind to as [`pCKB`](https://github.com/nervosnetwork/godwoken/blob/develop/docs/life_of_a_polyjuice_transaction.md#pCKB). The `eth_addr_reg_id` field in script args is the id of `ETH Address Registry` layer2 contract which provides two-ways mappings between `eth_address` and `gw_script_hash`.

### Contract account script

```
code_hash: polyjuice_validator_type_script_hash
hash_type: type
args:
    rollup_type_hash   : [u8; 32]
    creator_account_id : u32        (little endian, also chain id, and for reading 'sudt_id' from creator account script)
    info_data_hash     : [u8; 20]   (The information to be hashed is depend on how the account been created: [normal, create2], 
                                      the 20 bytes value is keccak256(info_data)[12..])
```

#### Normal contract account script
The Polyjuice contract account created in Polyjuice by `CREATE` call kind or Opcode.
```
info_content:
    sender_address  : [u8; 20]   (the msg.sender: blake128(sender_script) + account id)
    sender_nonce    : u32 
    
info_data: rlp_encode(sender_address, sender_nonce)
```

#### Create2 contract account script
The Polyjuice contract account created in Polyjuice by `CREATE2` Opcode.
```
info_data:
    special_byte    : u8         (value is '0xff', refer to Ethereum)
    sender_address  : [u8; 20]   (the msg.sender: blake128(sender_script) + account id)
    create2_salt    : [u8; 32]   (create2 salt)
    init_code_hash  : [u8; 32]   (keccak256(init_code))
```

### Address used in Polyjuice
In the latest version of Polyjuice, the [EOA](https://ethereum.org/en/glossary/#eoa) address is native `eth_address`, which is the rightmost 160 bits of a Keccak hash of an ECDSA public key. While the address for an Polyjuice contract is deterministically computed from the address of its creator (sender) and how many transactions the creator has sent (nonce). The sender and nonce are RLP encoded and then hashed with Keccak-256.


[rawl2tx-args]: https://github.com/nervosnetwork/godwoken/blob/develop/crates/types/schemas/godwoken.mol#L60
[meta-contract]: https://github.com/nervosnetwork/godwoken-scripts/blob/master/c/contracts/meta_contract.c

## More docs
* [EVM compatible](docs/EVM-compatible.md)
* [Addition Features](docs/Addition-Features.md)
* [Life of a Polyjuice Transaction](https://github.com/nervosnetwork/godwoken/blob/develop/docs/life_of_a_polyjuice_transaction.md)
* [Life of a Godwoken Transaction](https://github.com/nervosnetwork/godwoken/blob/develop/docs/life_of_a_godwoken_transaction.md)