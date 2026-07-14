// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the atomic ownership-handover `transferOwnership`. Access control, input
///      validation, and the stateless-rotate `InvalidSignature` branch are covered, plus the full
///      dual-signature happy path (a stateless recovery rotation AND a stateful owner-binding
///      signature over `(newOwner, nextCommitment)`) and its cross-binding check — all signed live.
contract ShrincsWallet_transferOwnership is ShrincsWalletTest {
    address internal NEW_OWNER = makeAddr("newOwner");

    /// @dev A structurally-valid next-key bundle to drive past argument decoding (the rotation
    ///      still fails verification with an empty recovery signature).
    function _nextKey() internal pure returns (ShrincsTypes.RotationTarget memory nextKey) {
        (nextKey,) = _makeRotationTarget("transfer-ownership-next-key");
    }

    /// @dev Stateful owner-binding signature cross-binding `newOwner` to the incoming bundle.
    function _ownerBindingSig(address newOwner, bytes32 nextCommitment)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory)
    {
        return _signStatefulAction(
            Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(newOwner, nextCommitment), 1
        );
    }

    function test_transferOwnership_revertsWhen_notOwner() public {
        ShrincsTypes.StatefulSignature memory ownerSig;
        ShrincsTypes.StatelessSignature memory recoverySig;
        ShrincsTypes.RotationTarget memory nextKey;
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER);
    }

    function test_transferOwnership_revertsWhen_zeroOwner() public {
        ShrincsTypes.StatefulSignature memory ownerSig;
        ShrincsTypes.StatelessSignature memory recoverySig;
        ShrincsTypes.RotationTarget memory nextKey;
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroAddressOwner.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, address(0));
    }

    function test_transferOwnership_revertsWhen_invalidRecoverySignature() public {
        // An empty recovery signature makes `statelessRotate` return the zero commitment,
        // surfaced as InvalidSignature.
        ShrincsTypes.StatefulSignature memory ownerSig;
        ShrincsTypes.StatelessSignature memory recoverySig;
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, _nextKey(), NEW_OWNER);
    }

    function test_transferOwnership_fullHandover() public {
        ShrincsTypes.RotationTarget memory nextKey = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        ShrincsTypes.StatelessSignature memory recoverySig = _signFullRotation(nextKey);
        ShrincsTypes.StatefulSignature memory ownerSig = _ownerBindingSig(NEW_OWNER, nextCommitment);

        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER);
        assertEq(wallet.owner(), NEW_OWNER, "classical owner handed over");
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "fresh bundle installed for the new owner");
        assertEq(factory.lastOwnerUpdate(address(wallet)), NEW_OWNER, "factory registry synced");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
    }

    function test_transferOwnership_crossBindingMismatch() public {
        // The stateless rotation succeeds, but a `newOwner` not matching the stateful owner-binding
        // signature's `(newOwner, nextCommitment)` payload fails verification.
        ShrincsTypes.RotationTarget memory nextKey = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        ShrincsTypes.StatelessSignature memory recoverySig = _signFullRotation(nextKey);
        ShrincsTypes.StatefulSignature memory ownerSig = _ownerBindingSig(NEW_OWNER, nextCommitment);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, makeAddr("wrongOwner"));
    }
}
