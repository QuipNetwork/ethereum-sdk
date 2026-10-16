// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ECDSA} from "solady-0.1.26/src/utils/ECDSA.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `quipSignedHashEcdsaTarget` — the EIP-712 typed-data digest the ERC-1271
///      ECDSA half must sign. The target is deterministic and domain-bound to this wallet.
contract ShrincsWallet_quipSignedHashEcdsaTarget is ShrincsWalletTest {
    function test_target_isOwnerSignable() public {
        bytes32 hash = keccak256("hello");
        bytes32 target = wallet.quipSignedHashEcdsaTarget(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, target);
        assertEq(ECDSA.recover(target, abi.encodePacked(r, s, v)), OWNER, "owner ECDSA recovers");
    }

    function test_target_isDeterministic() public view {
        bytes32 hash = keccak256("hello");
        assertEq(wallet.quipSignedHashEcdsaTarget(hash), wallet.quipSignedHashEcdsaTarget(hash));
    }

    function test_target_bindsTheMessageHash() public view {
        assertTrue(
            wallet.quipSignedHashEcdsaTarget(keccak256("a")) != wallet.quipSignedHashEcdsaTarget(keccak256("b")),
            "distinct messages produce distinct targets"
        );
    }

    function test_target_isNonZero() public view {
        assertTrue(wallet.quipSignedHashEcdsaTarget(bytes32(0)) != bytes32(0));
    }
}
