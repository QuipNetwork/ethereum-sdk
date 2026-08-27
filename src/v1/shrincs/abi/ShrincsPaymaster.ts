// Auto-generated from out/ShrincsPaymaster.sol/ShrincsPaymaster.json — do not edit by hand.
// Regenerate with `npm run copy-abi` after `forge build` when the contract interface changes.

export const shrincsPaymasterAbi = [
  {
    "type": "constructor",
    "inputs": [
      {
        "name": "shrincsVerifier_",
        "type": "address",
        "internalType": "address"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "ENTRY_POINT",
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
    "name": "addStake",
    "inputs": [
      {
        "name": "unstakeDelaySec",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
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
        "name": "pendingOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "deposit",
    "inputs": [],
    "outputs": [],
    "stateMutability": "payable"
  },
  {
    "type": "function",
    "name": "getDeposit",
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
    "name": "getShrincsVerifier",
    "inputs": [],
    "outputs": [
      {
        "name": "commitment",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "hashSuite",
        "type": "uint32",
        "internalType": "uint32"
      },
      {
        "name": "keyVersion",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "maxSignatures",
        "type": "uint32",
        "internalType": "uint32"
      },
      {
        "name": "statefulLeavesUsed",
        "type": "uint32",
        "internalType": "uint32"
      }
    ],
    "stateMutability": "view"
  },
  {
    "type": "function",
    "name": "initialize",
    "inputs": [
      {
        "name": "owner_",
        "type": "address",
        "internalType": "address"
      },
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
        "name": "hashSuite",
        "type": "uint32",
        "internalType": "uint32"
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
        "name": "leaf",
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
    "name": "markLeavesUsed",
    "inputs": [
      {
        "name": "leaves",
        "type": "uint32[]",
        "internalType": "uint32[]"
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
        "name": "result",
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
        "name": "pendingOwner",
        "type": "address",
        "internalType": "address"
      }
    ],
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
    "name": "postOp",
    "inputs": [
      {
        "name": "mode",
        "type": "uint8",
        "internalType": "enum IPaymaster.PostOpMode"
      },
      {
        "name": "context",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "actualGasCost",
        "type": "uint256",
        "internalType": "uint256"
      },
      {
        "name": "actualUserOpFeePerGas",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
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
    "name": "rotateStatefulKey",
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
    "stateMutability": "nonpayable"
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
    "name": "transferOwnership",
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
    "name": "unlockStake",
    "inputs": [],
    "outputs": [],
    "stateMutability": "nonpayable"
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
    "name": "validatePaymasterUserOp",
    "inputs": [
      {
        "name": "userOp",
        "type": "tuple",
        "internalType": "struct PackedUserOperation",
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
        "name": "",
        "type": "bytes32",
        "internalType": "bytes32"
      },
      {
        "name": "",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [
      {
        "name": "context",
        "type": "bytes",
        "internalType": "bytes"
      },
      {
        "name": "validationData",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "withdrawStake",
    "inputs": [
      {
        "name": "to",
        "type": "address",
        "internalType": "address payable"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
  },
  {
    "type": "function",
    "name": "withdrawTo",
    "inputs": [
      {
        "name": "to",
        "type": "address",
        "internalType": "address payable"
      },
      {
        "name": "amount",
        "type": "uint256",
        "internalType": "uint256"
      }
    ],
    "outputs": [],
    "stateMutability": "nonpayable"
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
      },
      {
        "name": "maxSignatures",
        "type": "uint32",
        "indexed": false,
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
    "name": "PaymasterInitialized",
    "inputs": [
      {
        "name": "owner",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "PaymasterValidationRejected",
    "inputs": [
      {
        "name": "wallet",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "reason",
        "type": "uint8",
        "indexed": false,
        "internalType": "enum IShrincsPaymaster.PaymasterValidationFailure"
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "ShrincsVerifierSet",
    "inputs": [
      {
        "name": "previousCommitment",
        "type": "bytes32",
        "indexed": false,
        "internalType": "bytes32"
      },
      {
        "name": "newCommitment",
        "type": "bytes32",
        "indexed": true,
        "internalType": "bytes32"
      },
      {
        "name": "hashSuite",
        "type": "uint32",
        "indexed": false,
        "internalType": "uint32"
      },
      {
        "name": "maxSignatures",
        "type": "uint32",
        "indexed": false,
        "internalType": "uint32"
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
    "name": "SponsorshipVerified",
    "inputs": [
      {
        "name": "wallet",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "leaf",
        "type": "uint32",
        "indexed": false,
        "internalType": "uint32"
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
    "name": "UserOpSponsored",
    "inputs": [
      {
        "name": "wallet",
        "type": "address",
        "indexed": true,
        "internalType": "address"
      },
      {
        "name": "mode",
        "type": "uint8",
        "indexed": true,
        "internalType": "enum IPaymaster.PostOpMode"
      },
      {
        "name": "actualGasCost",
        "type": "uint256",
        "indexed": false,
        "internalType": "uint256"
      },
      {
        "name": "actualUserOpFeePerGas",
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
    "name": "CommitmentMismatch",
    "inputs": []
  },
  {
    "type": "error",
    "name": "EmptyLeaves",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidEntryPoint",
    "inputs": []
  },
  {
    "type": "error",
    "name": "InvalidInitialization",
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
    "name": "ZeroMaxSignatures",
    "inputs": []
  }
] as const;
