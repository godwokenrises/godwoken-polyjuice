## Things don't compatible with EVM

* Transfer value can not exceed u128
* All address(EoA/contract) format are godwoken short address
* Create contract account returns godwoken short address
* transaction context
  - chain id is creator account id
  - block gas limit is `12500000`, and is not block level limit, every transaction can reach the limit
  - block difficulty is `2500000000000000`
* pre-compiled contract
  - `bn256_pairing` not supported yet，due to too high cycle cost (WIP)
* Call depth can **NOT** exceed 32, due to 4 MB maximum runtime memory for running contracts in [CKB VM](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0003-ckb-vm/0003-ckb-vm.md#risc-v-runtime-model).
