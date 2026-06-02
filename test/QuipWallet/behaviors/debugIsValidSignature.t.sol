// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_debugIsValidSignature is QuipWalletTest {
    function _ecdsaSign(
        uint256 privKey,
        bytes32 hash
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function test_debugIsValidSignature_returnsOkOnValidSig() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(3);

        bytes32 msgHash = keccak256("erc1271-debug-ok");
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            keys[1],
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[1], digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), msgHash)
        );

        bytes memory encoded = Codec.encodeErc1271Signature(
            keys[1],
            sig,
            ecdsa
        );
        assertEq(
            uint8(wallet.debugIsValidSignature(msgHash, encoded)),
            uint8(IQuipWallet.Erc1271ValidationResult.Ok)
        );
    }

    function test_debugIsValidSignature_returnsBadSignatureLengthOnWrongLength()
        public
    {
        _seedVerificationKeys(1);
        bytes32 msgHash = keccak256("erc1271-debug-len");

        IQuipWallet.Erc1271ValidationResult expected = IQuipWallet
            .Erc1271ValidationResult
            .BadSignatureLength;

        assertEq(
            uint8(wallet.debugIsValidSignature(msgHash, bytes(""))),
            uint8(expected)
        );
        assertEq(
            uint8(wallet.debugIsValidSignature(msgHash, new bytes(100))),
            uint8(expected)
        );
        assertEq(
            uint8(wallet.debugIsValidSignature(msgHash, new bytes(2208))),
            uint8(expected)
        );
        assertEq(
            uint8(wallet.debugIsValidSignature(msgHash, new bytes(2272))),
            uint8(expected)
        );
        assertEq(
            uint8(wallet.debugIsValidSignature(msgHash, new bytes(2274))),
            uint8(expected)
        );
    }

    function test_debugIsValidSignature_returnsInvalidEcdsaSignatureOnNonOwner()
        public
    {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(2);

        (, uint256 notOwnerKey) = makeAddrAndKey("debug-not-the-owner");
        bytes32 msgHash = keccak256("erc1271-debug-non-owner-ecdsa");
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            keys[0],
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        bytes memory ecdsa = _ecdsaSign(notOwnerKey, msgHash);

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    msgHash,
                    Codec.encodeErc1271Signature(keys[0], sig, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_debugIsValidSignature_returnsInvalidEcdsaSignatureOnWrongHash()
        public
    {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(2);

        bytes32 msgHash = keccak256("erc1271-debug-ecdsa-wrong-hash");
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            keys[0],
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            keccak256("not-the-actual-hash")
        );

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    msgHash,
                    Codec.encodeErc1271Signature(keys[0], sig, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_debugIsValidSignature_returnsInvalidEcdsaSignatureOnMalformedEcdsa()
        public
    {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(2);

        bytes32 msgHash = keccak256("erc1271-debug-malformed-ecdsa");
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            keys[0],
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        bytes memory ecdsa = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    msgHash,
                    Codec.encodeErc1271Signature(keys[0], sig, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    function test_debugIsValidSignature_returnsUnknownVerifierWhenVerifierNotInSet()
        public
    {
        _seedVerificationKeys(2);
        (
            WOTSPlus.WinternitzAddress memory outsider,
            bytes32 outsiderKey
        ) = _generateKeyPair("erc1271-debug-outsider");

        bytes32 msgHash = keccak256("erc1271-debug-outsider-msg");
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            outsider,
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(outsiderKey, digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), msgHash)
        );

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    msgHash,
                    Codec.encodeErc1271Signature(outsider, sig, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.UnknownVerifier)
        );
    }

    function test_debugIsValidSignature_returnsInvalidPqSignatureOnBadWotsSig()
        public
    {
        (WOTSPlus.WinternitzAddress[] memory keys, ) = _seedVerificationKeys(2);

        // Sign with a different WOTS+ private key — verifier known to wallet, but
        // signature won't verify against it.
        (, bytes32 wrongKey) = _generateKeyPair("erc1271-debug-wrong-key");
        bytes32 msgHash = keccak256("erc1271-debug-bad-sig");
        WOTSPlus.WinternitzElements memory bad = _sign(wrongKey, msgHash);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), msgHash)
        );

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    msgHash,
                    Codec.encodeErc1271Signature(keys[0], bad, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidPqSignature)
        );
    }

    /// @dev WOTS+ digest computed for one wallet but verified on another must
    ///      produce `InvalidPqSignature` (digest mismatch, not membership).
    function test_debugIsValidSignature_returnsInvalidPqSignatureOnWrongWalletBinding()
        public
    {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(2);

        bytes32 msgHash = keccak256("erc1271-debug-bound");
        bytes32 digest = _buildErc1271MessageHash(
            address(0xdeadbeef),
            keys[0],
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), msgHash)
        );

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    msgHash,
                    Codec.encodeErc1271Signature(keys[0], sig, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidPqSignature)
        );
    }

    /// @dev WOTS+ signed over digest(hash-A) but caller passes hash-B; ECDSA is
    ///      over hash-B (so the ECDSA branch passes). The mismatched WOTS+
    ///      digest is the failing branch.
    function test_debugIsValidSignature_returnsInvalidPqSignatureOnWrongMessageHash()
        public
    {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(2);

        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            keys[0],
            keccak256("debug-hash-A")
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), keccak256("debug-hash-B"))
        );

        assertEq(
            uint8(
                wallet.debugIsValidSignature(
                    keccak256("debug-hash-B"),
                    Codec.encodeErc1271Signature(keys[0], sig, ecdsa)
                )
            ),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidPqSignature)
        );
    }

    /// @dev All-zero 2273-byte payload bypasses the length check but the ECDSA
    ///      half recovers to `address(0)`, so the failure is reported as
    ///      `InvalidEcdsaSignature` — short-circuiting before keyset membership
    ///      is consulted. Mirrors `isValidSignature_emptySetRejectsAll` while
    ///      pinning the specific reason code.
    function test_debugIsValidSignature_zeroPayloadShortCircuitsAtEcdsa()
        public
        view
    {
        bytes memory anySig = new bytes(2273);
        assertEq(
            uint8(wallet.debugIsValidSignature(keccak256("x"), anySig)),
            uint8(IQuipWallet.Erc1271ValidationResult.InvalidEcdsaSignature)
        );
    }

    /// @dev `debugIsValidSignature` must be a pure read — calling it twice with
    ///      the same valid input must not consume the verifier key.
    function test_debugIsValidSignature_doesNotMutateSet() public {
        (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory priv
        ) = _seedVerificationKeys(3);

        uint256 before = wallet.keyCount(Codec.KeyType.Verification);
        bytes32 msgHash = keccak256("erc1271-debug-nomutate");
        bytes32 digest = _buildErc1271MessageHash(
            address(wallet),
            keys[0],
            msgHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(priv[0], digest);
        bytes memory ecdsa = _ecdsaSign(
            ALICE_KEY,
            _buildErc1271EcdsaTarget(address(wallet), msgHash)
        );
        bytes memory encoded = Codec.encodeErc1271Signature(
            keys[0],
            sig,
            ecdsa
        );

        wallet.debugIsValidSignature(msgHash, encoded);
        wallet.debugIsValidSignature(msgHash, encoded);

        assertEq(wallet.keyCount(Codec.KeyType.Verification), before);
        assertTrue(wallet.isKey(Codec.KeyType.Verification, keys[0]));
    }
}
