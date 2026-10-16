// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {FORSMinusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/FORSMinusC.sol";
import {Hypertree} from "@quip.network/hashsigs-solidity-0.2.0/contracts/Hypertree.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
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

    function _samplePublicKey() internal pure returns (SHRINCS.PublicKey memory pk) {
        pk.statefulPublicKey = abi.encodePacked(keccak256("spk-a"), keccak256("spk-b"), uint32(8));
        pk.publicKeyCommitment = abi.encodePacked(keccak256("commitment"));
        pk.pkSeed = abi.encodePacked(keccak256("pkSeed"));
        pk.hypertreeRoot = abi.encodePacked(keccak256("hypertreeRoot"));
    }

    function _sampleErc1271PublicKey() internal pure returns (SHRINCS.PublicKey memory pk) {
        pk.statefulPublicKey = abi.encodePacked(keccak256("epk-a"), keccak256("epk-b"), uint32(8));
        pk.publicKeyCommitment = abi.encodePacked(keccak256("epk-commit"));
        pk.pkSeed = abi.encodePacked(keccak256("epk-seed"));
        pk.hypertreeRoot = abi.encodePacked(keccak256("epk-root"));
    }

    function _sampleStatefulSig() internal pure returns (SHRINCS.Signature memory sig) {
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

    function _sampleStatelessSig() internal pure returns (SPHINCSPlusC.Signature memory sig) {
        sig.fors.randomizer = abi.encodePacked(keccak256("fors-randomizer"));
        sig.fors.counter = 11;
        sig.fors.entries = new FORSMinusC.ForsEntry[](0);
        sig.hypertree = new Hypertree.HypertreeLayerSignature[](0);
    }

    /* ───────────────────────────── equality helpers ────────────────────────── */

    function _assertPkEq(SHRINCS.PublicKey memory a, SHRINCS.PublicKey memory b) internal pure {
        assertEq(a.statefulPublicKey, b.statefulPublicKey, "statefulPublicKey");
        assertEq(a.publicKeyCommitment, b.publicKeyCommitment, "publicKeyCommitment");
        assertEq(a.pkSeed, b.pkSeed, "pkSeed");
        assertEq(a.hypertreeRoot, b.hypertreeRoot, "hypertreeRoot");
    }

    function _assertStatefulSigEq(SHRINCS.Signature memory a, SHRINCS.Signature memory b)
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
