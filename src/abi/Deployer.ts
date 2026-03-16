export const deployerAbi = [
  {
    "type": "function",
    "name": "deploy",
    "inputs": [
      {
        "name": "bytecode",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "salt",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "event",
    "name": "Deploy",
    "inputs": [
      {
        "name": "addr",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  }
] as const;
