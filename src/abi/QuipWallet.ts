export const quipWalletAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "creator",
        "type": "address",
        "internalType": "address payable"
      },
      {
        "name": "newOwner",
        "type": "address",
        "internalType": "address payable"
      }
    ],
    "stateMutability": "payable"
  },
  {
    "type": "fallback",
    "stateMutability": "payable"
  },
  {
    "type": "receive",
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "changePqOwner",
    "inputs": [
      {
        "name": "newPqOwner",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzAddress",
        "components": [
          {
            "name": "publicSeed",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "publicKeyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      },
      {
        "name": "pqSig",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzElements",
        "components": [
          {
            "name": "elements",
            "type": "bytes32[67]",
            "internalType": "bytes32[67]"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "executeWithWinternitz",
    "inputs": [
      {
        "name": "nextPqOwner",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzAddress",
        "components": [
          {
            "name": "publicSeed",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "publicKeyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      },
      {
        "name": "pqSig",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzElements",
        "components": [
          {
            "name": "elements",
            "type": "bytes32[67]",
            "internalType": "bytes32[67]"
          }
        ]
      },
      {
        "name": "target",
        "type": "address",
        "internalType": "address payable"
      },
      {
        "name": "opdata",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      },
      {
        "name": "",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "getExecuteFee",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getTransferFee",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "newPqOwner",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzAddress",
        "components": [
          {
            "name": "publicSeed",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "publicKeyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "owner",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address payable"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "pqOwner",
    "inputs": [],
    "outputs": [
      {
        "name": "publicSeed",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "publicKeyHash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "quipFactory",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address payable"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "transferWithWinternitz",
    "inputs": [
      {
        "name": "nextPqOwner",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzAddress",
        "components": [
          {
            "name": "publicSeed",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "publicKeyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      },
      {
        "name": "pqSig",
        "type": "tuple",
        "internalType": "struct WOTSPlus.WinternitzElements",
        "components": [
          {
            "name": "elements",
            "type": "bytes32[67]",
            "internalType": "bytes32[67]"
          }
        ]
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address payable"
      },
      {
        "name": "value",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "event",
    "name": "pqTransfer",
    "inputs": [
      {
        "name": "amount",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "when",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "pqFrom",
        "type": "tuple",
        "indexed": false,
        "internalType": "struct WOTSPlus.WinternitzAddress",
        "components": [
          {
            "name": "publicSeed",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "publicKeyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      },
      {
        "name": "pqNext",
        "type": "tuple",
        "indexed": false,
        "internalType": "struct WOTSPlus.WinternitzAddress",
        "components": [
          {
            "name": "publicSeed",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "publicKeyHash",
            "type": "bytes32",
            "internalType": "bytes32"
          }
        ]
      },
      {
        "name": "to",
        "type": "address",
        "indexed": false,
        "internalType": "address"
      }
    ],
    "anonymous": false
  }
] as const;
