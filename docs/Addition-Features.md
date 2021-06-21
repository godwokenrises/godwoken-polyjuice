
## Addition Features
* pre-compiled contract
  - Add `recover_account` for recover any supported signature
  - Add `balance_of_any_sudt` for query the balance of any sudt_id account
  - Add `transfer_to_any_sudt` for transfer value by sudt_id (Must collaborate with SudtErc20Proxy.sol contract)

### `recover_account` Spec

```
  Recover an EoA account script by signature

  input: (the input data is from abi.encode(mesage, signature, code_hash))
  ======
    input[ 0..32]  => message
    input[32..64]  => offset of signature part
    input[64..96]  => code_hash
    input[96..128] => length of signature data
    input[128..]   => signature data

  output:
  =======
    output[0..32] => data length
    output[..]    => account script data
```

### `balance_of_any_sudt` Spec

```
  Query the balance of `account_id` of `sudt_id` token.

   input:
   ======
     input[ 0..32] => sudt_id (big endian)
     input[32..64] => address (short_address)

   output:
   =======
     output[0..32] => amount
```

### `transfer_to_any_sudt` Spec

```
  Transfer `sudt_id` token from `from_id` to `to_id` with `amount` balance.

  NOTE: This pre-compiled contract need caller to check permission of `from_id`,
  currently only `solidity/erc20/SudtERC20Proxy.sol` is allowed to call this contract.

   input:
   ======
     input[ 0..32 ] => sudt_id (big endian)
     input[32..64 ] => from_addr (short address)
     input[64..96 ] => to_addr (short address)
     input[96..128] => amount (big endian)

   output: []
```
