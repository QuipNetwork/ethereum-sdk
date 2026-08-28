// Auto-generated from out/ShrincsWallet.sol/ShrincsWallet.json — do not edit by hand.
// Regenerate with `npm run copy-abi` after `forge build` when the contract interface changes.

export const shrincsWalletAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "factory_",
        "type": "address",
        "internalType": "address payable"
      },
      {
        "name": "shrincsVerifier_",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "nonpayable"
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
    "name": "FACTORY",
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
    "name": "SHRINCS_VERIFIER",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "actionNonce",
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
    "name": "addDeposit",
    "inputs": [],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "cancelOwnershipHandover",
    "inputs": [],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "completeOwnershipHandover",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "debugIsValidSignature",
    "inputs": [
      {
        "name": "hash",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signature",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint8",
        "internalType": "enum IShrincsWallet.Erc1271ValidationResult"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "delegateExecute",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
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
    "name": "eip712Domain",
    "inputs": [],
    "outputs": [
      {
        "name": "fields",
        "type": "bytes1",
        "internalType": "bytes1"
      },
      {
        "name": "name",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "version",
        "type": "string",
        "internalType": "string"
      },
      {
        "name": "chainId",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "verifyingContract",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "salt",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "extensions",
        "type": "uint256[]",
        "internalType": "uint256[]"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "entryPoint",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "execute",
    "inputs": [
      {
        "name": "publicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "signature",
        "type": "tuple",
        "internalType": "struct SHRINCS.Signature",
        "components": [
          {
            "name": "randomizer",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "counter",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "chains",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          },
          {
            "name": "authPath",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "target",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "value",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "maxFee",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "execute",
    "inputs": [
      {
        "name": "target",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "value",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "maxFee",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "execute",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
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
    "name": "executeBatch",
    "inputs": [
      {
        "name": "calls",
        "type": "tuple[]",
        "internalType": "struct ERC4337.Call[]",
        "components": [
          {
            "name": "target",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "value",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "data",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "maxFee",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "results",
        "type": "bytes[]",
        "internalType": "bytes[]"
      }
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "executeBatch",
    "inputs": [
      {
        "name": "",
        "type": "tuple[]",
        "internalType": "struct ERC4337.Call[]",
        "components": [
          {
            "name": "target",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "value",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "data",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes[]",
        "internalType": "bytes[]"
      }
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "getDeposit",
    "inputs": [],
    "outputs": [
      {
        "name": "result",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getErc1271Commitment",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getErc1271HashSuite",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "pure"
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
    "name": "getHashSuite",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "pure"
  },
  {
    "type": "function",
    "name": "getShrincsPublicKeyCommitment",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "getShrincsVerifier",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "newOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "newOwner",
        "type": "address",
        "internalType": "address payable"
      },
      {
        "name": "payload",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "isStatefulLeafUsed",
    "inputs": [
      {
        "name": "leafIndex",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bool",
        "internalType": "bool"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "isValidSignature",
    "inputs": [
      {
        "name": "hash",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "signature",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes4",
        "internalType": "bytes4"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "keyVersion",
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
    "name": "markLeavesUsed",
    "inputs": [
      {
        "name": "publicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "signature",
        "type": "tuple",
        "internalType": "struct SHRINCS.Signature",
        "components": [
          {
            "name": "randomizer",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "counter",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "chains",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          },
          {
            "name": "authPath",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "leaves",
        "type": "uint32[]",
        "internalType": "uint32[]"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "maxSignatures",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "migrate",
    "inputs": [
      {
        "name": "payload",
        "type": "bytes",
        "internalType": "bytes"
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
        "internalType": "address"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "ownershipHandoverExpiresAt",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "pure"
  },
  {
    "type": "function",
    "name": "proxiableUUID",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "quipSignedHashEcdsaTarget",
    "inputs": [
      {
        "name": "hash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "quipUserOpHashEcdsaTarget",
    "inputs": [
      {
        "name": "userOpHash",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "recoverWallet",
    "inputs": [
      {
        "name": "currentPublicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "recoverySignature",
        "type": "tuple",
        "internalType": "struct SPHINCSPlusC.Signature",
        "components": [
          {
            "name": "fors",
            "type": "tuple",
            "internalType": "struct FORSMinusC.ForsSignature",
            "components": [
              {
                "name": "randomizer",
                "type": "bytes",
                "internalType": "bytes"
              },
              {
                "name": "counter",
                "type": "uint32",
                "internalType": "uint32"
              },
              {
                "name": "entries",
                "type": "tuple[]",
                "internalType": "struct FORSMinusC.ForsEntry[]",
                "components": [
                  {
                    "name": "secretLeaf",
                    "type": "bytes",
                    "internalType": "bytes"
                  },
                  {
                    "name": "authPath",
                    "type": "bytes[]",
                    "internalType": "bytes[]"
                  }
                ]
              }
            ]
          },
          {
            "name": "hypertree",
            "type": "tuple[]",
            "internalType": "struct Hypertree.HypertreeLayerSignature[]",
            "components": [
              {
                "name": "wotsCPkHash",
                "type": "bytes",
                "internalType": "bytes"
              },
              {
                "name": "wotsCSignature",
                "type": "tuple",
                "internalType": "struct WOTSPlusC.WotsCSignature",
                "components": [
                  {
                    "name": "randomizer",
                    "type": "bytes",
                    "internalType": "bytes"
                  },
                  {
                    "name": "counter",
                    "type": "uint32",
                    "internalType": "uint32"
                  },
                  {
                    "name": "chains",
                    "type": "bytes[]",
                    "internalType": "bytes[]"
                  }
                ]
              },
              {
                "name": "authPath",
                "type": "bytes[]",
                "internalType": "bytes[]"
              }
            ]
          }
        ]
      },
      {
        "name": "nextKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.RotationTarget",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "remainingStatefulSignatures",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "renounceOwnership",
    "inputs": [],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "requestOwnershipHandover",
    "inputs": [],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "rotateKey",
    "inputs": [
      {
        "name": "currentPublicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "signature",
        "type": "tuple",
        "internalType": "struct SHRINCS.Signature",
        "components": [
          {
            "name": "randomizer",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "counter",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "chains",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          },
          {
            "name": "authPath",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "nextStatefulKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.StatefulRotationTarget",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "setErc1271Key",
    "inputs": [
      {
        "name": "publicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "signature",
        "type": "tuple",
        "internalType": "struct SHRINCS.Signature",
        "components": [
          {
            "name": "randomizer",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "counter",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "chains",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          },
          {
            "name": "authPath",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "newErc1271Commitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "newErc1271HashSuite",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "statefulLeafBitmapWord",
    "inputs": [
      {
        "name": "wordIndex",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
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
    "name": "statefulLeavesUsed",
    "inputs": [],
    "outputs": [
      {
        "name": "",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "storageLoad",
    "inputs": [
      {
        "name": "storageSlot",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "storageStore",
    "inputs": [
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "transferOwnership",
    "inputs": [
      {
        "name": "currentPublicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "ownerBindingSignature",
        "type": "tuple",
        "internalType": "struct SHRINCS.Signature",
        "components": [
          {
            "name": "randomizer",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "counter",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "chains",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          },
          {
            "name": "authPath",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "recoverySignature",
        "type": "tuple",
        "internalType": "struct SPHINCSPlusC.Signature",
        "components": [
          {
            "name": "fors",
            "type": "tuple",
            "internalType": "struct FORSMinusC.ForsSignature",
            "components": [
              {
                "name": "randomizer",
                "type": "bytes",
                "internalType": "bytes"
              },
              {
                "name": "counter",
                "type": "uint32",
                "internalType": "uint32"
              },
              {
                "name": "entries",
                "type": "tuple[]",
                "internalType": "struct FORSMinusC.ForsEntry[]",
                "components": [
                  {
                    "name": "secretLeaf",
                    "type": "bytes",
                    "internalType": "bytes"
                  },
                  {
                    "name": "authPath",
                    "type": "bytes[]",
                    "internalType": "bytes[]"
                  }
                ]
              }
            ]
          },
          {
            "name": "hypertree",
            "type": "tuple[]",
            "internalType": "struct Hypertree.HypertreeLayerSignature[]",
            "components": [
              {
                "name": "wotsCPkHash",
                "type": "bytes",
                "internalType": "bytes"
              },
              {
                "name": "wotsCSignature",
                "type": "tuple",
                "internalType": "struct WOTSPlusC.WotsCSignature",
                "components": [
                  {
                    "name": "randomizer",
                    "type": "bytes",
                    "internalType": "bytes"
                  },
                  {
                    "name": "counter",
                    "type": "uint32",
                    "internalType": "uint32"
                  },
                  {
                    "name": "chains",
                    "type": "bytes[]",
                    "internalType": "bytes[]"
                  }
                ]
              },
              {
                "name": "authPath",
                "type": "bytes[]",
                "internalType": "bytes[]"
              }
            ]
          }
        ]
      },
      {
        "name": "nextKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.RotationTarget",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "newOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "transferOwnership",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "upgradeToAndCall",
    "inputs": [
      {
        "name": "newImplementation",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "validateUserOp",
    "inputs": [
      {
        "name": "userOp",
        "type": "tuple",
        "internalType": "struct ERC4337.PackedUserOperation",
        "components": [
          {
            "name": "sender",
            "type": "address",
            "internalType": "address"
          },
          {
            "name": "nonce",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "initCode",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "callData",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "accountGasLimits",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "preVerificationGas",
            "type": "uint256",
            "internalType": "uint256"
          },
          {
            "name": "gasFees",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "paymasterAndData",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "signature",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "userOpHash",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "missingAccountFunds",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "validationData",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "verifyUpgrade",
    "inputs": [
      {
        "name": "newImplementation",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "data",
        "type": "bytes",
        "internalType": "bytes"
      }
    ],
    "outputs": [],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "version",
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
    "name": "walletFactory",
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
    "name": "withdrawDepositTo",
    "inputs": [
      {
        "name": "",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "withdrawDepositTo",
    "inputs": [
      {
        "name": "publicKey",
        "type": "tuple",
        "internalType": "struct SHRINCS.PublicKey",
        "components": [
          {
            "name": "statefulPublicKey",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "publicKeyCommitment",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "pkSeed",
            "type": "bytes",
            "internalType": "bytes"
          },
          {
            "name": "hypertreeRoot",
            "type": "bytes",
            "internalType": "bytes"
          }
        ]
      },
      {
        "name": "signature",
        "type": "tuple",
        "internalType": "struct SHRINCS.Signature",
        "components": [
          {
            "name": "randomizer",
            "type": "bytes32",
            "internalType": "bytes32"
          },
          {
            "name": "counter",
            "type": "uint32",
            "internalType": "uint32"
          },
          {
            "name": "chains",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          },
          {
            "name": "authPath",
            "type": "bytes32[]",
            "internalType": "bytes32[]"
          }
        ]
      },
      {
        "name": "to",
        "type": "address",
        "internalType": "address"
      },
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "event",
    "name": "Erc1271KeySet",
    "inputs": [
      {
        "name": "oldCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "newCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "ExecutionSucceeded",
    "inputs": [
      {
        "name": "target",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "value",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "dataHash",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Initialized",
    "inputs": [
      {
        "name": "version",
        "type": "uint64",
        "indexed": false,
        "internalType": "uint64"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "KeyRotated",
    "inputs": [
      {
        "name": "previousCommitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "nextCommitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "keyVersion",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LeafConsumedOnly",
    "inputs": [
      {
        "name": "leaf",
        "type": "uint32",
        "indexed": true,
        "internalType": "uint32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LeafRevocationSkipped",
    "inputs": [
      {
        "name": "leaf",
        "type": "uint32",
        "indexed": true,
        "internalType": "uint32"
      },
      {
        "name": "keyVersion",
        "type": "uint256",
        "indexed": true,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LeafRevoked",
    "inputs": [
      {
        "name": "leaf",
        "type": "uint32",
        "indexed": true,
        "internalType": "uint32"
      },
      {
        "name": "keyVersion",
        "type": "uint256",
        "indexed": true,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "OwnershipHandoverCanceled",
    "inputs": [
      {
        "name": "pendingOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "OwnershipHandoverRequested",
    "inputs": [
      {
        "name": "pendingOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "OwnershipTransferred",
    "inputs": [
      {
        "name": "oldOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "newOwner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "StatefulSignatureVerified",
    "inputs": [
      {
        "name": "leaf",
        "type": "uint32",
        "indexed": true,
        "internalType": "uint32"
      },
      {
        "name": "keyVersion",
        "type": "uint256",
        "indexed": true,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "Upgraded",
    "inputs": [
      {
        "name": "implementation",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "UserOpValidationRejected",
    "inputs": [
      {
        "name": "reason",
        "type": "uint8",
        "indexed": true,
        "internalType": "enum IShrincsWallet.UserOpValidationFailure"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "WalletInitialized",
    "inputs": [
      {
        "name": "factory",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "owner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "shrincsPublicKeyCommitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "erc1271StatelessCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "WalletMigrated",
    "inputs": [
      {
        "name": "shrincsPublicKeyCommitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "keyVersion",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      }
    ],
    "anonymous": false
  },
  {
    "type": "error",
    "name": "AlreadyInitialized",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ClassicalTransferOwnershipDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ClassicalWithdrawDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "CommitmentMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "DelegateExecuteDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "EmptyLeaves",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ExecuteFeeExceedsCap",
    "inputs": [
      {
        "name": "fee",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "maxFee",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "FnSelectorNotRecognized",
    "inputs": []
  },
  {
    "type": "error",
    "name": "GuardedSlotTampered",
    "inputs": [
      {
        "name": "slotIndex",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "IdentityMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ImplementationDeprecated",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ImplementationNotVetted",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidFactory",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidInitialization",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidSignature",
    "inputs": []
  },
  {
    "type": "error",
    "name": "LeafOutOfRange",
    "inputs": [
      {
        "name": "leaf",
        "type": "uint32",
        "internalType": "uint32"
      }
    ]
  },
  {
    "type": "error",
    "name": "MalformedPayload",
    "inputs": [
      {
        "name": "expectedMin",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "actual",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "NewOwnerIsZeroAddress",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NoHandoverRequest",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotInitializing",
    "inputs": []
  },
  {
    "type": "error",
    "name": "NotUpgrading",
    "inputs": []
  },
  {
    "type": "error",
    "name": "OwnershipHandoverDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "RenounceDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "StaleActionNonce",
    "inputs": [
      {
        "name": "expected",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "provided",
        "type": "uint256",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "error",
    "name": "StaleStatefulLeaf",
    "inputs": []
  },
  {
    "type": "error",
    "name": "StandardExecuteDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "StatefulBudgetExhausted",
    "inputs": []
  },
  {
    "type": "error",
    "name": "StatefulTreeSpent",
    "inputs": [
      {
        "name": "treeId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "StatelessTreeSpent",
    "inputs": [
      {
        "name": "treeId",
        "type": "bytes32",
        "internalType": "bytes32"
      }
    ]
  },
  {
    "type": "error",
    "name": "StorageStoreDisabled",
    "inputs": []
  },
  {
    "type": "error",
    "name": "Unauthorized",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UnauthorizedCallContext",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UnsupportedHashSuite",
    "inputs": []
  },
  {
    "type": "error",
    "name": "UpgradeFailed",
    "inputs": []
  },
  {
    "type": "error",
    "name": "VerifierProfileMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAddressFactory",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAddressOwner",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroAddressVerifier",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroErc1271Commitment",
    "inputs": []
  },
  {
    "type": "error",
    "name": "ZeroMaxSignatures",
    "inputs": []
  }
] as const;
