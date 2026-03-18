// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory/QuipFactory.t.sol";
import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title QuipWallet Base Test
/// @dev Base contract for testing QuipWallet. Inherits full stack from QuipFactoryTest
///      and deploys a wallet for ALICE.
contract QuipWalletTest is QuipFactoryTest {
    QuipWallet public wallet;
    WOTSPlus.WinternitzAddress public alicePubkey;
    bytes32 public alicePrivateKey;
    bytes32 public constant VAULT_SEED = "alice-vault-1";

    function setUp() public virtual override {
        super.setUp();

        // Deploy a wallet for ALICE with initial deposit
        address walletAddr;
        (walletAddr, alicePubkey, alicePrivateKey) = _createWallet(
            ALICE,
            VAULT_SEED,
            INITIAL_DEPOSIT
        );
        wallet = QuipWallet(payable(walletAddr));
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
    }

    // --- Wallet-specific helpers ---

    /// @dev Build the transfer message hash for signing
    function _buildTransferMessageHash(
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address to,
        uint256 value
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                to,
                value
            )
        );
    }

    /// @dev Build the execute message hash for signing
    function _buildExecuteMessageHash(
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address target,
        bytes memory opdata
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                target,
                opdata
            )
        );
    }

    /// @dev Build the changePqOwner message hash for signing
    function _buildChangePqOwnerMessageHash(
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory newPq
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                newPq.publicSeed,
                newPq.publicKeyHash
            )
        );
    }
}
