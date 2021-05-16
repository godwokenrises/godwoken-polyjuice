pragma solidity >=0.6.0 <=0.8.2;

contract EthToPolyjuiceAddress {
  function calcAddr(bytes32 lock_code_hash, address eth_addr) public returns (address) {
      uint256[2] memory input;
      input[0] = uint256(lock_code_hash);
      input[1] = uint256(uint160(eth_addr));
      uint256[1] memory output;

      assembly {
          if iszero(call(not(0), 0xf2, 0x0, input, 0x40, output, 0x20)) {
              revert(0x0, 0x0)
          }
      }
      return address(uint160(output[0]));
  }
}
