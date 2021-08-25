
The content of `SudtERC20Proxy.ContractCode.hex` is copied from running `test_cases::sudt_erc20_proxy::test_sudt_erc20_proxy`.

```
# Generate the contract code hash of SudtERC20Proxy
$ ckb-cli util blake2b --binary-hex [SudtERC20Proxy.ContractCode.hex]
0x84fca35d11d31b80bd6b49e62450307af842bed3d61232fe90af6d555ad93aa5

# Generate the contract code hash of SudtERC20Proxy_UserDefinedDecimals
$ ckb-cli util blake2b --binary-hex [SudtERC20Proxy_UserDefinedDecimals.ContractCode.hex]
0x1d8516872890ddf85b01d354463459e576f27453f152120cd722be30059e9ad8
```

The code hash above will be checked in `transfer_to_any_sudt` pre-compiled contract.
