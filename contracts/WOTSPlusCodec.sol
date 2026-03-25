// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title WOTSPlusCodec
/// @dev Payload layout (all offsets in bytes):
///      [0:64)      WinternitzAddress     — pqOwner (publicSeed ++ publicKeyHash)
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:2848) WinternitzAddress[10] — recoveryKeys (10 x 64)
///      [2848:)     bytes                 — verifier data (variable length)
///
///      Constants:
///        RECOVERY_KEY_AMOUNT = 10
///
///      Offset derivation:
///        PQ_OWNER  = 2 x 32                          = 64
///        PQ_SIG    = 67 x 32                          = 2144   → starts at 64
///        REC_KEYS  = RECOVERY_KEY_AMOUNT x 64         = 640    → starts at 64 + 2144 = 2208
///        VERIFIERS                                             → starts at 2208 + 640 = 2848
library WOTSPlusCodec {

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         DECODERS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function extractPqOwner(bytes calldata payload)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress calldata owner)
    {
        assembly {
            owner := payload.offset // 0
        }
    }

    function extractPqSig(bytes calldata payload)
        internal
        pure
        returns (WOTSPlus.WinternitzElements calldata sig)
    {
        assembly {
            sig := add(payload.offset, 64) // PQ_OWNER_SIZE
        }
    }

    function extractRecoveryKeys(bytes calldata payload)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[10] calldata keys)
    {
        assembly {
            keys := add(payload.offset, 2208) // PQ_OWNER_SIZE + PQ_SIG_SIZE
        }
    }

    function extractVerifiers(bytes calldata payload)
        internal
        pure
        returns (bytes calldata)
    {
        return payload[2848:]; // PQ_OWNER_SIZE + PQ_SIG_SIZE + RECOVERY_KEYS_SIZE
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ENCODERS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function encode(
        WOTSPlus.WinternitzAddress memory owner,
        WOTSPlus.WinternitzElements memory sig,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory result = abi.encodePacked(
            owner.publicSeed,
            owner.publicKeyHash,
            sig.elements
        );
        for (uint256 i = 0; i < 10; i++) {
            result = abi.encodePacked(
                result,
                recoveryKeys[i].publicSeed,
                recoveryKeys[i].publicKeyHash
            );
        }
        return result;
    }

    function encode(
        WOTSPlus.WinternitzAddress memory owner,
        WOTSPlus.WinternitzElements memory sig,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys,
        bytes memory verifiers
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(encode(owner, sig, recoveryKeys), verifiers);
    }
}
