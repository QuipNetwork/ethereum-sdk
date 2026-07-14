// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

contract EpTarget {
    uint256 public x;

    function setX(uint256 v) external payable {
        x = v;
    }

    receive() external payable {}
}

/// @dev Behavior tests for the ERC-4337 `execute(address,uint256,bytes,uint256 maxFee)` overload
///      (the `onlyEntryPoint`-gated path that runs after `_validateSignature`). No SHRINCS
///      verification happens here — `maxFee` is signed by riding in `callData` under userOpHash —
///      so both the access gate and the fee-cap semantics are fully testable now. The inherited
///      un-capped `execute(address,uint256,bytes)` must be dead (`StandardExecuteDisabled`).
contract ShrincsWallet_execute_erc4337 is ShrincsWalletTest {
    EpTarget internal target;

    function setUp() public override {
        super.setUp();
        target = new EpTarget();
    }

    function test_execute_revertsWhen_callerNotEntryPoint() public {
        vm.prank(makeAddr("notEntryPoint"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(address(target), 0, "", 0);
    }

    function test_execute_revertsWhen_callerIsOwner() public {
        // Only the EntryPoint may use this overload — even the owner is rejected.
        vm.prank(OWNER);
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(address(target), 0, "", 0);
    }

    function test_execute_transfersEthAndCollectsFee() public {
        uint256 fee = 0.01 ether;
        uint256 value = 0.5 ether;
        factory.setExecuteFee(fee);
        vm.deal(WALLET, value + fee);

        uint256 factoryBefore = address(factory).balance;
        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), value, "", fee);

        assertEq(address(target).balance, value, "value delivered");
        assertEq(address(factory).balance - factoryBefore, fee, "fee collected to factory");
        assertEq(address(WALLET).balance, 0, "wallet drained of value + fee");
    }

    function test_execute_callsContract() public {
        factory.setExecuteFee(0);
        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), 0, abi.encodeCall(EpTarget.setX, (42)), 0);
        assertEq(target.x(), 42, "contract call executed");
    }

    function test_execute_noFeeWhenZero() public {
        factory.setExecuteFee(0);
        uint256 factoryBefore = address(factory).balance;
        vm.deal(WALLET, 1 ether);
        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), 0, "", 0);
        assertEq(address(factory).balance, factoryBefore, "no fee transfer when fee == 0");
    }

    /// @dev Cap semantics: the LIVE fee is charged, `maxFee` is only a ceiling — a fee decrease
    ///      between signing and landing succeeds at the lower price.
    function test_execute_chargesLiveFeeBelowCap() public {
        factory.setExecuteFee(0.01 ether);
        vm.deal(WALLET, 1 ether);
        uint256 factoryBefore = address(factory).balance;

        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), 0, "", 0.05 ether); // signed headroom above the live fee

        assertEq(address(factory).balance - factoryBefore, 0.01 ether, "live fee charged, not maxFee");
    }

    /// @dev A live fee above the signed ceiling reverts in the execution phase. (The e2e suite
    ///      asserts the validation-phase leaf/nonce consumption that precedes this revert.)
    function test_execute_revertsWhen_feeExceedsCap() public {
        factory.setExecuteFee(0.02 ether);
        vm.deal(WALLET, 1 ether);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.ExecuteFeeExceedsCap.selector, 0.02 ether, 0.01 ether));
        wallet.execute(address(target), 0, "", 0.01 ether);
    }

    /// @dev The inherited un-capped selector is dead for EVERY caller — otherwise a userOp could
    ///      route `callData` through it and execute with no signed fee ceiling.
    function test_execute_standardSelectorDisabled() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(IShrincsWallet.StandardExecuteDisabled.selector);
        wallet.execute(address(target), 0, "");

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StandardExecuteDisabled.selector);
        wallet.execute(address(target), 0, "");

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsWallet.StandardExecuteDisabled.selector);
        wallet.execute(address(target), 0, "");
    }
}
