// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodecHarness} from "../harness/ShrincsWalletCodecHarness.sol";

/// @title ShrincsWalletCodec Base Test
/// @dev Deploys the codec harness and provides in-memory sample structs + equality helpers for the
///      decode round-trip and builder tests.
contract ShrincsWalletCodecTest is Test {
    ShrincsWalletCodecHarness internal codec;

    function setUp() public virtual {
        codec = new ShrincsWalletCodecHarness();
    }

    /* ───────────────────────────── sample structs ──────────────────────────── */

    function _samplePublicKey() internal pure returns (ShrincsTypes.PublicKey memory pk) {
        pk.statefulPublicKey = abi.encodePacked(keccak256("spk-a"), keccak256("spk-b"), uint32(8));
        pk.publicKeyCommitment = abi.encodePacked(keccak256("commitment"));
        pk.pkSeed = abi.encodePacked(keccak256("pkSeed"));
        pk.hypertreeRoot = abi.encodePacked(keccak256("hypertreeRoot"));
    }

    function _sampleStatefulSig() internal pure returns (ShrincsTypes.StatefulSignature memory sig) {
        sig.randomizer = keccak256("randomizer");
        sig.counter = 7;
        sig.chains = new bytes32[](2);
        sig.chains[0] = keccak256("chain-0");
        sig.chains[1] = keccak256("chain-1");
        sig.authPath = new bytes32[](3); // leaf 3
        sig.authPath[0] = keccak256("auth-0");
        sig.authPath[1] = keccak256("auth-1");
        sig.authPath[2] = keccak256("auth-2");
    }

    function _sampleStatelessSig() internal pure returns (ShrincsTypes.StatelessSignature memory sig) {
        sig.fors.randomizer = abi.encodePacked(keccak256("fors-randomizer"));
        sig.fors.counter = 11;
        sig.fors.entries = new ShrincsTypes.ForsEntry[](0);
        sig.hypertree = new ShrincsTypes.HypertreeLayerSignature[](0);
    }

    /* ───────────────────────────── equality helpers ────────────────────────── */

    function _assertPkEq(ShrincsTypes.PublicKey memory a, ShrincsTypes.PublicKey memory b) internal pure {
        assertEq(a.statefulPublicKey, b.statefulPublicKey, "statefulPublicKey");
        assertEq(a.publicKeyCommitment, b.publicKeyCommitment, "publicKeyCommitment");
        assertEq(a.pkSeed, b.pkSeed, "pkSeed");
        assertEq(a.hypertreeRoot, b.hypertreeRoot, "hypertreeRoot");
    }

    function _assertStatefulSigEq(ShrincsTypes.StatefulSignature memory a, ShrincsTypes.StatefulSignature memory b)
        internal
        pure
    {
        assertEq(a.randomizer, b.randomizer, "randomizer");
        assertEq(a.counter, b.counter, "counter");
        assertEq(a.chains.length, b.chains.length, "chains length");
        for (uint256 i; i < a.chains.length; i++) {
            assertEq(a.chains[i], b.chains[i], "chains[i]");
        }
        assertEq(a.authPath.length, b.authPath.length, "authPath length");
        for (uint256 i; i < a.authPath.length; i++) {
            assertEq(a.authPath[i], b.authPath[i], "authPath[i]");
        }
    }
}
