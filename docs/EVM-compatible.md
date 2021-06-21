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
