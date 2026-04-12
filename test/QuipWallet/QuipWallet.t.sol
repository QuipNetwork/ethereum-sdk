// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory/QuipFactory.t.sol";
import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

/// @title QuipWallet Base Test
/// @dev Base contract for testing QuipWallet. Inherits full stack from QuipFactoryTest
///      and deploys a wallet for ALICE.
contract QuipWalletTest is QuipFactoryTest {
    QuipWallet public wallet;
    WOTSPlus.WinternitzAddress public alicePubkey;
    bytes32 public alicePrivateKey;
    WOTSPlus.WinternitzAddress[] public recoveryPubkeys;
    bytes32 public constant VAULT_SEED = "alice-vault-1";

    function setUp() public virtual override {
        super.setUp();

        // Deploy a wallet for ALICE with initial deposit
        address walletAddr;
        WOTSPlus.WinternitzAddress[] memory rPubkeys;
        (walletAddr, alicePubkey, alicePrivateKey, rPubkeys) = _createWallet(
            ALICE,
            VAULT_SEED,
            INITIAL_DEPOSIT
        );
        wallet = QuipWallet(payable(walletAddr));

        for (uint256 i = 0; i < rPubkeys.length; i++) {
            recoveryPubkeys.push(rPubkeys[i]);
        }
    }

    function test_setUp() public view override {
        // Inherited checks
        assertEq(factory.owner(), ADMIN);

        // Wallet checks
        assertEq(wallet.owner(), ALICE);
        assertEq(address(wallet.quipFactory()), address(factory));
        assertEq(address(wallet).balance, INITIAL_DEPOSIT);

        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, alicePubkey.publicSeed);
        assertEq(publicKeyHash, alicePubkey.publicKeyHash);

        // Recovery key checks
        assertEq(wallet.getRecoveryKeyCount(), 10);
    }

    // --- Wallet-specific helpers ---

    function _buildExecuteMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address target,
        uint256 value,
        bytes memory data,
        uint256 fee
    ) internal view returns (bytes32) {
        return Codec.executeDigest(
            wallet_, block.chainid,
            currentPq.publicSeed, currentPq.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash,
            target, value, keccak256(data), fee
        );
    }

    function _buildChangePqOwnerMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory newPq
    ) internal view returns (bytes32) {
        return Codec.keyRotationDigest(
            wallet_, block.chainid,
            currentPq.publicSeed, currentPq.publicKeyHash,
            newPq.publicSeed, newPq.publicKeyHash
        );
    }

    function _buildRecoverWalletMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzAddress memory newPq
    ) internal view returns (bytes32) {
        return Codec.keyRotationDigest(
            wallet_, block.chainid,
            recoveryKey.publicSeed, recoveryKey.publicKeyHash,
            newPq.publicSeed, newPq.publicKeyHash
        );
    }

    function _buildAddRecoveryKeysMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes32) {
        return Codec.keyManagementDigest(
            wallet_, block.chainid,
            currentPq.publicSeed, currentPq.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash,
            keccak256(abi.encode(newKeys))
        );
    }

    function _buildReplenishRecoveryKeysMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes32) {
        return Codec.keyManagementDigest(
            wallet_, block.chainid,
            currentPq.publicSeed, currentPq.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash,
            keccak256(abi.encode(newKeys))
        );
    }

    function _buildTransferOwnershipMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address newOwner
    ) internal view returns (bytes32) {
        return Codec.transferOwnershipDigest(
            wallet_, block.chainid,
            currentPq.publicSeed, currentPq.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash,
            newOwner
        );
    }

    function _buildCompleteOwnershipHandoverMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address pendingOwner
    ) internal view returns (bytes32) {
        return Codec.completeOwnershipHandoverDigest(
            wallet_, block.chainid,
            currentPq.publicSeed, currentPq.publicKeyHash,
            nextPq.publicSeed, nextPq.publicKeyHash,
            pendingOwner
        );
    }

    function _buildRecoveryUpgradeMessageHash(
        address wallet_,
        address newImplementation,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory recoveryKey
    ) internal view returns (bytes32) {
        return Codec.upgradeRecoveryDigest(
            wallet_, block.chainid, newImplementation,
            currentPq.publicSeed, currentPq.publicKeyHash,
            recoveryKey.publicSeed, recoveryKey.publicKeyHash
        );
    }
}
