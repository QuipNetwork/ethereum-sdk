// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/WOTSPlusTestSigner.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/deprecated/wots/WOTSPlusCodec.sol";

/// @title WOTS+ key fixtures
/// @dev Pure, deterministic WOTS+ keyset derivation shared by the WalletFactory test base and
///      the invariant handlers that must build deploy payloads without being test contracts
///      themselves (a handler that inherits a concrete test base is discovered by forge as a
///      test suite of its own).
abstract contract WOTSKeyFixtures {
    /// @dev Generate recovery key public keys from a private key
    function _generateRecoveryKeys(
        bytes32 privateKey,
        uint256 count
    ) internal pure returns (WOTSPlus.WinternitzAddress[] memory pubkeys) {
        pubkeys = new WOTSPlus.WinternitzAddress[](count);
        for (uint256 i = 0; i < count; i++) {
            bytes32 seed = keccak256(
                abi.encodePacked(privateKey, "recovery", i)
            );
            (pubkeys[i], ) = WOTSPlusTestSigner.generateKeyPair(seed);
        }
    }

    /// @dev Derive the disaster recovery keypair deterministically from a vault seed.
    ///      Tests that exercise `saveWallet` can re-derive the same keypair by feeding
    ///      the vault seed back in.
    function _generateDisasterRecoveryKey(
        bytes32 vaultSeed
    )
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "disaster"));
        (pubkey, privateKey) = WOTSPlusTestSigner.generateKeyPair(seed);
    }

    /// @dev Derive the ownership keypair deterministically from a vault seed.
    ///      Tests that exercise `transferOwnership` can re-derive the same
    ///      keypair by feeding the vault seed back in.
    function _generateOwnershipKey(
        bytes32 vaultSeed
    )
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey)
    {
        bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "ownership"));
        (pubkey, privateKey) = WOTSPlusTestSigner.generateKeyPair(seed);
    }

    /// @dev Generate the 10 initial transaction keys deterministically from a vault seed.
    function _generateTransactionKeys(
        bytes32 vaultSeed
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress[10] memory pubkeys,
            bytes32[10] memory privateKeys
        )
    {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "txn", i));
            (pubkeys[i], privateKeys[i]) = WOTSPlusTestSigner.generateKeyPair(seed);
        }
    }

    /// @dev Generate the 10 initial verification keys deterministically from a vault seed.
    function _generateVerificationKeys(
        bytes32 vaultSeed
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress[10] memory pubkeys,
            bytes32[10] memory privateKeys
        )
    {
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(abi.encodePacked(vaultSeed, "verify", i));
            (pubkeys[i], privateKeys[i]) = WOTSPlusTestSigner.generateKeyPair(seed);
        }
    }

    /// @dev Builds the encoded init payload for `_createWalletFull` without
    ///      holding all stack slots in the parent (stack-too-deep avoidance
    ///      after the always-10 growth bumped the encoded layout).
    function _buildInitPayloadForCreate(
        bytes32 vaultSeed,
        WOTSPlus.WinternitzAddress[10] memory txnPubkeys,
        WOTSPlus.WinternitzAddress[] memory recoveryPubkeys
    ) internal pure returns (bytes memory) {
        (
            WOTSPlus.WinternitzAddress memory disasterKey,

        ) = _generateDisasterRecoveryKey(vaultSeed);
        (
            WOTSPlus.WinternitzAddress memory ownershipKey,

        ) = _generateOwnershipKey(vaultSeed);
        WOTSPlus.WinternitzAddress[10] memory recFixed;
        for (uint256 i = 0; i < 10; i++) {
            recFixed[i] = recoveryPubkeys[i];
        }
        (
            WOTSPlus.WinternitzAddress[10] memory verifPubkeys,

        ) = _generateVerificationKeys(vaultSeed);
        return
            Codec.encodeInit(
                disasterKey,
                ownershipKey,
                txnPubkeys,
                recFixed,
                verifPubkeys
            );
    }
}
