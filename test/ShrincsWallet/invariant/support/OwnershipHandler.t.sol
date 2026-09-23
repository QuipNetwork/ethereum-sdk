// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";

contract ShrincsWalletOwnershipHandler is Test {
    ShrincsWalletHarness internal wallet;
    SHRINCS.PublicKey internal oldPublicKey;
    SHRINCS.PublicKey internal newPublicKey;
    SHRINCS.Signature internal oldKeySignature;
    SHRINCS.Signature internal freshSignature;
    SHRINCS.Signature internal acceptanceLeafSignature;
    address internal oldOwner;
    address internal newOwner;
    address internal target;
    bool public freshActionExecuted;
    uint256 public oldOwnerRejections;
    uint256 public oldKeyRejections;
    uint256 public acceptanceReplayRejections;
    uint256 public freshActionReplays;

    function initialize(
        ShrincsWalletHarness wallet_,
        SHRINCS.PublicKey calldata oldPublicKey_,
        SHRINCS.PublicKey calldata newPublicKey_,
        SHRINCS.Signature calldata oldKeySignature_,
        SHRINCS.Signature calldata freshSignature_,
        SHRINCS.Signature calldata acceptanceLeafSignature_,
        address oldOwner_,
        address newOwner_,
        address target_
    ) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        oldPublicKey = oldPublicKey_;
        newPublicKey = newPublicKey_;
        oldKeySignature = oldKeySignature_;
        freshSignature = freshSignature_;
        acceptanceLeafSignature = acceptanceLeafSignature_;
        oldOwner = oldOwner_;
        newOwner = newOwner_;
        target = target_;
    }

    function fuzzOldOwnerCannotExecute() external {
        vm.prank(oldOwner);
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(newPublicKey, freshSignature, target, 0, "", 0);
        oldOwnerRejections++;
    }

    function fuzzOldKeyCannotExecute() external {
        vm.prank(newOwner);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(oldPublicKey, oldKeySignature, target, 0, "", 0);
        oldKeyRejections++;
    }

    function fuzzAcceptanceLeafCannotExecute() external {
        vm.prank(newOwner);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.execute(newPublicKey, acceptanceLeafSignature, target, 0, "", 0);
        acceptanceReplayRejections++;
    }

    function fuzzNewOwnerExecutes() external {
        vm.prank(newOwner);
        if (freshActionExecuted) {
            vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
            wallet.execute(newPublicKey, freshSignature, target, 0, "", 0);
            freshActionReplays++;
        } else {
            wallet.execute(newPublicKey, freshSignature, target, 0, "", 0);
            freshActionExecuted = true;
        }
    }
}
