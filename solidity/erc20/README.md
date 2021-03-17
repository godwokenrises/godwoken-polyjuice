
The content of the file `./SudtERC20Proxy.ContractCode.hex` is copy from running `test_cases::sudt_erc20_proxy::test_sudt_erc20_proxy`, and `./SudtERC20Proxy.ContractCode.bin` is the binary format of it.


Generate the contract code hash of SudtERC20Proxy:
```
$ ckb-cli util blake2b --binary-path ./SudtERC20Proxy.ContractCode.bin
0x7e92a77f129e70c8a950a6e7090c3149769482773f1ad5dae6cd9d022abbbcb5
```

The code hash above will be checked in `transfer_to_any_sudt` pre-compiled contract.
