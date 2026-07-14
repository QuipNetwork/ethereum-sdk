// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `setErc1271Key`. Reverts plus the success path (commitment +
///      suite updated, `Erc1271KeySet`) are all exercised.
contract ShrincsWallet_setErc1271Key is ShrincsWalletTest {
    bytes32 internal constant NEW_COMMITMENT = keccak256("new-erc1271");
    uint32 internal constant SUITE = HashSuite.HASH_SUITE_ID;

    function test_setErc1271Key_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(1), NEW_COMMITMENT, SUITE);
    }

    function test_setErc1271Key_revertsWhen_zeroCommitment() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(1), bytes32(0), SUITE);
    }

    function test_setErc1271Key_revertsWhen_unsupportedHashSuite() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(1), NEW_COMMITMENT, SHRINCS.HASH_SUITE_UNSUPPORTED);
    }

    function test_setErc1271Key_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(0), NEW_COMMITMENT, SUITE);
    }

    function test_setErc1271Key_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), NEW_COMMITMENT, SUITE);
    }

    function test_setErc1271Key_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(1), NEW_COMMITMENT, SUITE);
    }

    function test_setErc1271Key_revertsWhen_invalidSignature() public {
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.setErc1271Key(_mainPk(), sig, NEW_COMMITMENT, SUITE);
    }

    function test_setErc1271Key_succeeds() public {
        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_SET_ERC1271_KEY, Codec.setErc1271KeyPayloadHash(NEW_COMMITMENT, SUITE), 1
        );
        bytes32 old = wallet.getErc1271Commitment();
        vm.expectEmit(false, false, false, true, address(wallet));
        emit IShrincsWallet.Erc1271KeySet(old, NEW_COMMITMENT);
        vm.prank(OWNER);
        wallet.setErc1271Key(_mainPk(), sig, NEW_COMMITMENT, SUITE);
        assertEq(wallet.getErc1271Commitment(), NEW_COMMITMENT);
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the action nonce");
    }
}
