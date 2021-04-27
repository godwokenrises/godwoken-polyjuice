
# Godwoken polyjuice
An Ethereum compatible backend for [Godwoken](https://github.com/nervosnetwork/godwoken) rollup framework. It include generator and validator implementations.

### Features
- [x] All op codes
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

### Creator account script
```
code_hash: polyjuice_validator_type_script_hash
hash_type: type | data
args:
    rollup_type_hash : [u8; 32]
    sudt_id          : u32          (little endian, the token id)
```

### Normal contract account script
```
code_hash: polyjuice_validator_type_script_hash
hash_type: type | data
args:
    rollup_type_hash   : [u8; 32]
    creator_account_id : u32        (little endian, also chain id, for reading 'sudt_id' from creator account script)
    sender_account_id  : u32        (little endian)
    sender_nonce       : u32        (little endian)
```

### Create2 contract account script
```
code_hash: polyjuice_validator_type_script_hash
hash_type: type | data
args:
    rollup_type_hash   : [u8; 32]
    creator_account_id : u32        (little endian, also chain id, for reading 'sudt_id' from creator account script)
    special_byte       : u8         (value is '0xff', refer to ethereum)
    sender_account_id  : u32        (little endian)
    create2_salt       : [u8; 32]   (create2 salt)
    init_code_hash     : [u8; 32]   (keccak256(init_code))
```
