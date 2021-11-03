
# Godwoken Polyjuice
An Ethereum compatible backend for [Godwoken](https://github.com/nervosnetwork/godwoken) rollup framework. It include generator and validator implementations.

Polyjuice provides an [Ethereum](https://ethereum.org/en/) compatible layer on [Nervos CKB](https://github.com/nervosnetwork/ckb). It leverages account model as well as scalability provided by [Godwoken](./life_of_a_godwoken_transaction.md), then integrates [evmone](https://github.com/ethereum/evmone) as an EVM engine for running Ethereum smart contracts.

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
header     : [u8; 8]  (header[0..7] = "ETHPOLY",
                       header[7]    = call_kind { 0: CALL, 3: CREATE })
gas_limit  : u64      (little endian)
gas_price  : u128     (little endian)
value      : u128     (little endian)
input_size : u32      (little endian)
input_data : [u8; input_size]   (input data)
```

Every Polyjuice argument fields must been serialized one by one and put into godwoken [`RawL2Transaction.args`][rawl2tx-args] for polyjuice to read. If the `input_data` have 56 bytes, then the serialized data size is `8 + 8 + 16 + 16 + 4 + 56 = 108` bytes.


### Creator account script
```
code_hash: Polyjuice_validator_type_script_hash
hash_type: type
args:
    rollup_type_hash : [u8; 32]
    sudt_id          : u32          (little endian, the token id)
```

Polyjuice creator account is a godwoken account for creating Polyjuice contract account. This account can only been created by [meta contract][meta-contract], and the account id is used as the chain id in Polyjuice. The `sudt_id` field in script args is the sudt token current Polyjuice instance bind to.

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
    special_byte    : u8         (value is '0xff', refer to ethereum)
    sender_address  : [u8; 20]   (the msg.sender: blake128(sender_script) + account id)
    create2_salt    : [u8; 32]   (create2 salt)
    init_code_hash  : [u8; 32]   (keccak256(init_code))
```

### Address used in Polyjuice
In the latest version of Polyjuice, the [EOA](https://ethereum.org/en/glossary/#eoa) addresses are native `eth_address`, which is the rightmost 160 bits of a Keccak hash of an ECDSA public key.

In the previous version of Polyjuice, all the addresses are `short_godwoken_account_script_hash`, which is:
``` rust
short_godwoken_account_script_hash = blake2b(script.as_slice())[0..20]
```

| polyjuice_args_header | EOA address type |
| - | - |
| `header[0..7] = "ETHPOLY"` | native `eth_address` |
| `header[0] = 0xff,`<br>`header[1] = 0xff,`<br>`header[2] = 0xff,`<br>`header[3..7] = "POLY"`| short_godwoken_account_script_hash |


[rawl2tx-args]: https://github.com/nervosnetwork/godwoken/blob/9a3d921/crates/types/schemas/godwoken.mol#L60
[meta-contract]: https://github.com/nervosnetwork/godwoken-scripts/blob/028dbc4/c/contracts/meta_contract.c

## More docs
* [EVM compatible](docs/EVM-compatible.md)
* [Addition Features](docs/Addition-Features.md)
* [Life of a Polyjuice Transaction](https://github.com/nervosnetwork/godwoken/blob/master/docs/life_of_a_polyjuice_transaction.md)
* [Life of a Godwoken Transaction](https://github.com/nervosnetwork/godwoken/blob/master/docs/life_of_a_godwoken_transaction.md)