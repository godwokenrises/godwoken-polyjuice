pragma solidity >=0.4.0 <=0.8.0;

contract BlockInfo {
  bytes32 blockHash;
  uint difficulty;
  uint gasLimit;
  uint number;
  uint timestamp;
  address coinbase;

  constructor() public payable {
    blockHash = blockhash(0);
    difficulty = block.difficulty;
    gasLimit = block.gaslimit;
    number = block.number;
    timestamp = block.timestamp;
    coinbase = block.coinbase;
    require(coinbase == 0x0400000000000000000000000000000000000000);
    require(blockHash == 0x0707070707070707070707070707070707070707070707070707070707070707);
    require(gasLimit == 12500000);
  }

  function getGenesisHash() public view returns (bytes32) {
    return blockHash;
  }

  function getDifficulty() public view returns (uint) {
    return difficulty;
  }
  function getGasLimit() public view returns (uint) {
    return gasLimit;
  }
  function getNumber() public view returns (uint) {
    return number;
  }
  function getTimestamp() public view returns (uint) {
    return timestamp;
  }
  function getCoinbase() public view returns (address) {
    return coinbase;
  }
}
