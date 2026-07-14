// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Minimal EntryPoint stand-in: `ERC4337.withdrawDepositTo` calls `withdrawTo(address,uint256)`
///      behind an `extcodesize` guard, so the canonical EntryPoint address must carry code that
///      accepts the call. The catch-all fallback succeeds for any selector.
contract MockEntryPointStub {
    fallback() external payable {}

    receive() external payable {}
}

/// @dev Behavior tests for owner-path `withdrawDepositTo(PublicKey,StatefulSignature,address,uint256)`.
contract ShrincsWallet_withdrawDepositTo is ShrincsWalletTest {
    address internal constant TO = address(0xD00D);

    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _mainPk();
    }

    function test_withdraw_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.withdrawDepositTo(_pk(), _statefulSigWithLeaf(1), TO, 1 ether);
    }

    function test_withdraw_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.withdrawDepositTo(_pk(), _statefulSigWithLeaf(0), TO, 1 ether);
    }

    function test_withdraw_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.withdrawDepositTo(_pk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), TO, 1 ether);
    }

    function test_withdraw_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.withdrawDepositTo(_pk(), _statefulSigWithLeaf(1), TO, 1 ether);
    }

    function test_withdraw_revertsWhen_invalidSignature() public {
        ShrincsTypes.StatefulSignature memory sig = _wrongContextStatefulSig();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.withdrawDepositTo(_pk(), sig, TO, 1 ether);
    }

    function test_withdraw_succeeds() public {
        // Sign the WITHDRAW context over (TO, amount 0). `ERC4337.withdrawDepositTo` forwards to
        // the canonical EntryPoint, so etch a stub there that accepts `withdrawTo`.
        vm.etch(ENTRY_POINT, address(new MockEntryPointStub()).code);
        ShrincsTypes.StatefulSignature memory sig =
            _signStatefulAction(Codec.ACTION_WITHDRAW, Codec.withdrawPayloadHash(TO, 0), 1);
        vm.prank(OWNER);
        wallet.withdrawDepositTo(_pk(), sig, TO, 0);
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
    }
}
