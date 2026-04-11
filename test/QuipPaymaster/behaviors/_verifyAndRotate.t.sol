// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymasterHarness} from "../../harness/QuipPaymasterHarness.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipPaymaster__verifyAndRotate is QuipPaymasterTest {
    /// @dev Domain tag for paymaster approval digests (must match QuipPaymaster._PAYMASTER_APPROVE_TAG).
    bytes32 private constant _PAYMASTER_APPROVE_TAG = keccak256("quip.digest.paymasterApprove");

    function test_exposed_verifyAndRotate_returnsTrueAndRotates() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("verifier-seed-1");
        bytes32 userOpHash = keccak256("test-userop");

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            userOpHash
        );

        WOTSPlus.WinternitzElements memory sig = _sign(verifierPrivateKey, digest);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(WALLET, userOpHash, paymasterData);
        assertTrue(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, nextPubkey.publicSeed);
        assertEq(stored.publicKeyHash, nextPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_emitsPqVerifierRotated() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("verifier-seed-1");
        bytes32 userOpHash = keccak256("test-userop-event");

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            userOpHash
        );

        WOTSPlus.WinternitzElements memory sig = _sign(verifierPrivateKey, digest);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        vm.recordLogs();
        harness.exposed_verifyAndRotate(WALLET, userOpHash, paymasterData);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], IQuipPaymaster.PqVerifierRotated.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(WALLET))));
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_zeroNextVerifierSeed() public {
        bytes32 userOpHash = keccak256("test-userop-zero-seed");

        WOTSPlus.WinternitzElements memory sig = _sign(verifierPrivateKey, userOpHash);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            bytes32(0),                         // zero publicSeed
            verifierPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(WALLET, userOpHash, paymasterData);
        assertFalse(valid);

        // Verifier unchanged
        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_zeroNextVerifierHash() public {
        bytes32 userOpHash = keccak256("test-userop-zero-hash");

        WOTSPlus.WinternitzElements memory sig = _sign(verifierPrivateKey, userOpHash);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey.publicSeed,
            bytes32(0),                         // zero publicKeyHash
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(WALLET, userOpHash, paymasterData);
        assertFalse(valid);

        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_noVerifier() public {
        address unregistered = makeAddr("unregistered");

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("verifier-seed-2");
        bytes32 userOpHash = keccak256("test-userop-2");

        WOTSPlus.WinternitzElements memory sig = _sign(verifierPrivateKey, userOpHash);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(unregistered, userOpHash, paymasterData);
        assertFalse(valid);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_keyReuse() public {
        bytes32 userOpHash = keccak256("test-userop-3");

        WOTSPlus.WinternitzElements memory sig = _sign(verifierPrivateKey, userOpHash);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(WALLET, userOpHash, paymasterData);
        assertFalse(valid);

        // Verifier unchanged
        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_exposed_verifyAndRotate_returnsFalseWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("verifier-seed-invalid");
        bytes32 userOpHash = keccak256("test-userop-invalid");

        // Sign with a wrong key (not the installed verifier's private key)
        (, bytes32 wrongPrivateKey) = _generateKeyPair("wrong-key");
        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(harness)))),
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            userOpHash
        );

        WOTSPlus.WinternitzElements memory sig = _sign(wrongPrivateKey, digest);

        bytes memory paymasterData = abi.encodePacked(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPubkey.publicSeed,
            nextPubkey.publicKeyHash,
            sig.elements
        );

        bool valid = harness.exposed_verifyAndRotate(WALLET, userOpHash, paymasterData);
        assertFalse(valid);

        // Verifier unchanged
        WOTSPlus.WinternitzAddress memory stored = harness.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, verifierPubkey.publicSeed);
        assertEq(stored.publicKeyHash, verifierPubkey.publicKeyHash);
    }
}
