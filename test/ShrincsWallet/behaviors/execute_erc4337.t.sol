// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

contract EpTarget {
    uint256 public x;

    function setX(uint256 v) external payable {
        x = v;
    }

    receive() external payable {}
}

/// @dev Behavior tests for the ERC-4337 `execute(address,uint256,bytes)` overload (the
///      `onlyEntryPoint`-gated path that runs after `_validateSignature`). No SHRINCS verification
///      happens here, so both the access gate and the success path are fully testable now.
contract ShrincsWallet_execute_erc4337 is ShrincsWalletTest {
    EpTarget internal target;

    function setUp() public override {
        super.setUp();
        target = new EpTarget();
    }

    function test_execute_revertsWhen_callerNotEntryPoint() public {
        vm.prank(makeAddr("notEntryPoint"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(address(target), 0, "");
    }

    function test_execute_revertsWhen_callerIsOwner() public {
        // Only the EntryPoint may use this overload — even the owner is rejected.
        vm.prank(OWNER);
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(address(target), 0, "");
    }

    function test_execute_transfersEthAndCollectsFee() public {
        uint256 fee = 0.01 ether;
        uint256 value = 0.5 ether;
        factory.setExecuteFee(fee);
        vm.deal(WALLET, value + fee);

        uint256 factoryBefore = address(factory).balance;
        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), value, "");

        assertEq(address(target).balance, value, "value delivered");
        assertEq(address(factory).balance - factoryBefore, fee, "fee collected to factory");
        assertEq(address(WALLET).balance, 0, "wallet drained of value + fee");
    }

    function test_execute_callsContract() public {
        factory.setExecuteFee(0);
        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), 0, abi.encodeCall(EpTarget.setX, (42)));
        assertEq(target.x(), 42, "contract call executed");
    }

    function test_execute_noFeeWhenZero() public {
        factory.setExecuteFee(0);
        uint256 factoryBefore = address(factory).balance;
        vm.deal(WALLET, 1 ether);
        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), 0, "");
        assertEq(address(factory).balance, factoryBefore, "no fee transfer when fee == 0");
    }
}
