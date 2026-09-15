// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

contract BatchTarget {
    uint256 public sum;

    function add(uint256 v) external payable {
        sum += v;
    }

    receive() external payable {}
}

/// @dev Behavior tests for the ERC-4337 `executeBatch(Call[],uint256 maxFee)` overload
///      (`onlyEntryPoint`, no SHRINCS — `maxFee` is signed by riding in `callData`). One fee per
///      batch. The inherited un-capped `executeBatch(Call[])` must be dead.
contract ShrincsWallet_executeBatch is ShrincsWalletTest {
    BatchTarget internal target;

    function setUp() public override {
        super.setUp();
        target = new BatchTarget();
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertTrue(address(target).code.length > 0, "batch target deployed");
        assertEq(target.sum(), 0, "batch target pristine");
    }

    function _calls() internal view returns (ERC4337.Call[] memory calls) {
        calls = new ERC4337.Call[](2);
        calls[0] = ERC4337.Call({target: address(target), value: 0, data: abi.encodeCall(BatchTarget.add, (3))});
        calls[1] = ERC4337.Call({target: address(target), value: 0, data: abi.encodeCall(BatchTarget.add, (4))});
    }

    function test_executeBatch_revertsWhen_callerNotEntryPoint() public {
        vm.prank(makeAddr("notEntryPoint"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.executeBatch(_calls(), 0);
    }

    function test_executeBatch_runsAllCallsAndCollectsFee() public {
        uint256 fee = 0.02 ether;
        _setExecuteFee(fee);
        vm.deal(WALLET, fee);
        uint256 factoryBefore = address(factory).balance;

        vm.prank(ENTRY_POINT);
        wallet.executeBatch(_calls(), fee);

        assertEq(target.sum(), 7, "both calls executed");
        assertEq(address(factory).balance - factoryBefore, fee, "single fee collected for the batch");
    }

    function test_executeBatch_revertsWhen_feeExceedsCap() public {
        _setExecuteFee(0.02 ether);
        vm.deal(WALLET, 1 ether);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.ExecuteFeeExceedsCap.selector, 0.02 ether, 0.01 ether));
        wallet.executeBatch(_calls(), 0.01 ether);

        assertEq(target.sum(), 0, "no call executed past the cap");
    }

    function test_executeBatch_standardSelectorDisabled() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(IShrincsWallet.StandardExecuteDisabled.selector);
        wallet.executeBatch(_calls());

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsWallet.StandardExecuteDisabled.selector);
        wallet.executeBatch(_calls());
    }
}
