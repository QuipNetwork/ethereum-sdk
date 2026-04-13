// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_isValidSignature is QuipWalletTest {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;

    function test_isValidSignature_returnsMagicValueOnValidSig() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeyset(3);

        bytes32 msgHash = keccak256("erc1271-valid");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), keys[1], msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(priv[1], digest);

        bytes memory encoded = Codec.encodeErc1271Signature(keys[1], sig);
        assertEq(wallet.isValidSignature(msgHash, encoded), MAGIC);
    }

    function test_isValidSignature_doesNotMutateSet() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeyset(3);

        uint256 before = wallet.getVerificationKeyCount();
        bytes32 msgHash = keccak256("erc1271-nomutate");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), keys[0], msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);

        wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], sig));
        wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], sig));

        assertEq(wallet.getVerificationKeyCount(), before);
        assertTrue(wallet.isVerificationKey(keys[0]));
    }

    function test_isValidSignature_returnsFailureOnVerifierNotInSet() public {
        _seedVerificationKeyset(2);
        (WOTSPlus.WinternitzAddress memory outsider, bytes32 outsiderKey) =
            _generateKeyPair("erc1271-outsider");

        bytes32 msgHash = keccak256("erc1271-outsider-msg");
        bytes32 digest = _buildErc1271MessageHash(address(wallet), outsider, msgHash);
        WOTSPlus.WinternitzElements memory sig = _sign(outsiderKey, digest);

        assertEq(
            wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(outsider, sig)),
            FAIL
        );
    }

    function test_isValidSignature_returnsFailureOnBadSignature() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
        ) = _seedVerificationKeyset(2);

        // Sign with a different private key to produce a structurally valid but invalid sig
        (, bytes32 wrongKey) = _generateKeyPair("erc1271-wrong-key");
        bytes32 msgHash = keccak256("erc1271-bad-sig");
        WOTSPlus.WinternitzElements memory bad = _sign(wrongKey, msgHash);

        assertEq(
            wallet.isValidSignature(msgHash, Codec.encodeErc1271Signature(keys[0], bad)),
            FAIL
        );
    }

    function test_isValidSignature_returnsFailureOnWrongMessageHash() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeyset(2);

        bytes32 digest = _buildErc1271MessageHash(
            address(wallet), keys[0], keccak256("hash-A")
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);

        assertEq(
            wallet.isValidSignature(
                keccak256("hash-B"),
                Codec.encodeErc1271Signature(keys[0], sig)
            ),
            FAIL
        );
    }

    function test_isValidSignature_isBoundToWallet() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeyset(2);

        // Sign a digest bound to a different wallet address.
        bytes32 digest = _buildErc1271MessageHash(
            address(0xdeadbeef), keys[0], keccak256("hash-bound")
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);

        assertEq(
            wallet.isValidSignature(
                keccak256("hash-bound"),
                Codec.encodeErc1271Signature(keys[0], sig)
            ),
            FAIL
        );
    }

    function test_isValidSignature_returnsFailureOnWrongLength() public {
        _seedVerificationKeyset(1);
        bytes32 msgHash = keccak256("erc1271-len");

        assertEq(wallet.isValidSignature(msgHash, bytes("")), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(100)), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(2207)), FAIL);
        assertEq(wallet.isValidSignature(msgHash, new bytes(2209)), FAIL);
    }

    function test_isValidSignature_emptySetRejectsAll() public view {
        bytes memory anySig = new bytes(2208);
        assertEq(wallet.isValidSignature(keccak256("x"), anySig), FAIL);
    }
}
