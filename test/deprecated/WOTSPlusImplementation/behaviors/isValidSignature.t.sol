// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

contract WOTSPlusImplementation_isValidSignature is WOTSPlusImplementationTest {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;

    /// @dev ECDSA-sign `hash` with the given private key; returns a 65-byte (r ++ s ++ v) packed sig.
    function _ecdsaSign(uint256 privKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function test_isValidSignature_returnsMagicValueOnValidSig() public {
        (WOTSPlus.WinternitzAddress[] memory keys, bytes32[] memory priv) = _seedVerificationKeys(3);
        bytes32 msgHash = keccak256("erc1271-valid");
        // ECDSA half signs the EIP-712 wrap, not the raw `msgHash`.
        bytes memory encoded = _encodeValidErc1271Signature(keys[1], priv[1], msgHash);
        assertEq(wallet.isValidSignature(msgHash, encoded), MAGIC);
    }

    function test_isValidSignature_doesNotMutateSet() public {
        (bytes32 msgHash, WOTSPlus.WinternitzAddress memory key, bytes memory encoded, uint256 before) =
            _prepareErc1271MutationCheck("erc1271-nomutate");

        wallet.isValidSignature(msgHash, encoded);
        wallet.isValidSignature(msgHash, encoded);

        _assertVerificationKeyUnconsumed(before, key);
    }

    function test_isValidSignature_returnsFailureOnVerifierNotInSet() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory outsider, bytes32 outsiderKey) = _generateKeyPair("erc1271-outsider");

        bytes32 msgHash = keccak256("erc1271-outsider-msg");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), outsider, msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(outsiderKey, digest);
        bytes memory ecdsa = _ecdsaSign(ALICE_KEY, _buildErc1271EcdsaTarget(address(wallet), msgHash));

        assertEq(wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(outsider, sig, ecdsa)), FAIL);
    }

    function test_isValidSignature_returnsFailureOnBadWotsSignature() public {
        (WOTSPlus.WinternitzAddress[] memory keys,) = _seedVerificationKeys(2);

        // Sign with a different WOTS+ private key to produce a structurally valid but invalid sig.
        (, bytes32 wrongKey) = _generateKeyPair("erc1271-wrong-key");
        bytes32 msgHash = keccak256("erc1271-bad-sig");
        WOTSPlus.WinternitzElements memory bad = _sign(wrongKey, msgHash);
        // Valid ECDSA so the test isolates the WOTS+ failure path.
        bytes memory ecdsa = _ecdsaSign(ALICE_KEY, _buildErc1271EcdsaTarget(address(wallet), msgHash));

        assertEq(wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], bad, ecdsa)), FAIL);
    }

    function test_isValidSignature_returnsFailureOnWrongMessageHash() public {
        (WOTSPlus.WinternitzAddress[] memory keys, bytes32[] memory priv) = _seedVerificationKeys(2);

        bytes32 digest = _buildErc1271MessageHash(address(wallet), keys[0], keccak256("hash-A"));
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        // ECDSA half is valid for the caller-passed hash (hash-B); the
        // failure isolates the WOTS+ "wrong message hash" branch.
        bytes memory ecdsa = _ecdsaSign(ALICE_KEY, _buildErc1271EcdsaTarget(address(wallet), keccak256("hash-B")));

        assertEq(wallet.isValidSignature(keccak256("hash-B"), Codec.encodeErc1271Signature(keys[0], sig, ecdsa)), FAIL);
    }

    function test_isValidSignature_isBoundToWallet() public {
        (WOTSPlus.WinternitzAddress[] memory keys, bytes32[] memory priv) = _seedVerificationKeys(2);

        bytes32 msgHash = keccak256("hash-bound");
        // Sign a WOTS+ digest bound to a different wallet address.
        bytes32 digest = _buildErc1271MessageHash(address(0xdeadbeef), keys[0], msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        // Valid ECDSA against this wallet so the failure isolates the
        // WOTS+ wallet-binding branch.
        bytes memory ecdsa = _ecdsaSign(ALICE_KEY, _buildErc1271EcdsaTarget(address(wallet), msgHash));

        assertEq(wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], sig, ecdsa)), FAIL);
    }

    /// @dev ECDSA half signed by a wallet that is not the classical owner must fail.
    function test_isValidSignature_returnsFailureOnEcdsaFromNonOwner() public {
        (WOTSPlus.WinternitzAddress[] memory keys, bytes32[] memory priv) = _seedVerificationKeys(2);

        (, uint256 notOwnerKey) = makeAddrAndKey("not-the-owner");
        bytes32 msgHash = keccak256("erc1271-non-owner-ecdsa");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), keys[0], msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        // Non-owner key signs the correct EIP-712 target → recovery yields
        // an address that is not `owner()` → ECDSA branch rejects.
        bytes memory ecdsa = _ecdsaSign(notOwnerKey, _buildErc1271EcdsaTarget(address(wallet), msgHash));

        assertEq(wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], sig, ecdsa)), FAIL);
    }

    /// @dev ECDSA half over a different hash than the one the caller passes must fail.
    function test_isValidSignature_returnsFailureOnEcdsaWrongHash() public {
        (WOTSPlus.WinternitzAddress[] memory keys, bytes32[] memory priv) = _seedVerificationKeys(2);

        bytes32 msgHash = keccak256("erc1271-ecdsa-wrong-hash");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), keys[0], msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        // ECDSA signs the EIP-712 wrap of a DIFFERENT hash; caller passes
        // `msgHash`. Contract recovers against `wrap(msgHash)`, which
        // yields an address that is not `owner()` → ECDSA branch rejects.
        bytes memory ecdsa =
            _ecdsaSign(ALICE_KEY, _buildErc1271EcdsaTarget(address(wallet), keccak256("not-the-actual-hash")));

        assertEq(wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], sig, ecdsa)), FAIL);
    }

    /// @dev ECDSA half with structurally malformed bytes (non-recoverable) must fail.
    function test_isValidSignature_returnsFailureOnMalformedEcdsa() public {
        (WOTSPlus.WinternitzAddress[] memory keys, bytes32[] memory priv) = _seedVerificationKeys(2);

        bytes32 msgHash = keccak256("erc1271-malformed-ecdsa");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), keys[0], msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        // 65-byte ECDSA sig with v = 0 (invalid — valid v is 27 or 28).
        bytes memory ecdsa = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        assertEq(wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], sig, ecdsa)), FAIL);
    }

    function test_isValidSignature_returnsFailureOnWrongLength() public {
        _seedVerificationKeys(1);
        bytes32 msgHash = keccak256("erc1271-len");

        assertEq(wallet.isValidSignature(msgHash, bytes("")), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(100)), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(2208)), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(2272)), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(2274)), FAIL);
    }

    function test_isValidSignature_emptySetRejectsAll() public view {
        bytes memory anySig = new bytes(2273);
        assertEq(wallet.isValidSignature(keccak256("x"), anySig), FAIL);
    }
}
