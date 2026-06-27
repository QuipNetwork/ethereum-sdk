// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

contract BatchTarget {
    uint256 public sum;

    function add(uint256 v) external payable {
        sum += v;
    }

    receive() external payable {}
}

/// @dev Behavior tests for the ERC-4337 `executeBatch` overload (`onlyEntryPoint`, no SHRINCS).
contract ShrincsWallet_executeBatch is ShrincsWalletTest {
    BatchTarget internal target;

    function setUp() public override {
        super.setUp();
        target = new BatchTarget();
    }

    function _calls() internal view returns (ERC4337.Call[] memory calls) {
        calls = new ERC4337.Call[](2);
        calls[0] = ERC4337.Call({target: address(target), value: 0, data: abi.encodeCall(BatchTarget.add, (3))});
        calls[1] = ERC4337.Call({target: address(target), value: 0, data: abi.encodeCall(BatchTarget.add, (4))});
    }

    function test_executeBatch_revertsWhen_callerNotEntryPoint() public {
        vm.prank(makeAddr("notEntryPoint"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.executeBatch(_calls());
    }

    function test_executeBatch_runsAllCallsAndCollectsFee() public {
        uint256 fee = 0.02 ether;
        factory.setExecuteFee(fee);
        vm.deal(WALLET, fee);
        uint256 factoryBefore = address(factory).balance;

        vm.prank(ENTRY_POINT);
        wallet.executeBatch(_calls());

        assertEq(target.sum(), 7, "both calls executed");
        assertEq(address(factory).balance - factoryBefore, fee, "single fee collected for the batch");
    }
}
