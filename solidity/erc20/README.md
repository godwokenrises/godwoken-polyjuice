For security reason, developers should only use this [SudtERC20Proxy_UserDefinedDecimals bytecode](./SudtERC20Proxy_UserDefinedDecimals.bin) which code hash will be checked in `transfer_to_any_sudt` pre-compiled contract.

Note: SudtERC20Proxy.sol will be deprecated.

## Compile Solidity Contract in ethereum/solc:0.8.7 docker image
Here is the method that we compile SudtERC20Proxy_UserDefinedDecimals.sol.
```sh
> docker run -v $(pwd):/contracts ethereum/solc:0.8.7 -o /contracts --abi --bin --overwrite /contracts/SudtERC20Proxy_UserDefinedDecimals.sol

> sha256sum ERC20.bin 
9f7bf1ab25b377ddc339e6de79a800d4c7dc83de7e12057a0129b467794ce3a3  ERC20.bin
```

## Generate Code Hash

The content of `SudtERC20Proxy_UserDefinedDecimals.ContractCode.hex` is copied from running `test_cases::sudt_erc20_proxy::test_sudt_erc20_proxy_user_defined_decimals`.

```sh
# Generate the contract code hash of SudtERC20Proxy_UserDefinedDecimals
$ ckb-cli util blake2b --binary-hex [the content string of SudtERC20Proxy_UserDefinedDecimals.ContractCode.hex]

0xa816b946a890cd593f780e8b6859a9b82314c5df4c8270d66f7c502e818345dc
```

The code hash above will be checked in `transfer_to_any_sudt` pre-compiled contract.
