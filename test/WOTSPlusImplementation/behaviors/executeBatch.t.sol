// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";

/// @dev Inline target: counter that also accepts ETH and echoes its current value.
contract BatchTarget {
    uint256 public count;

    function inc() external payable {
        count += 1;
    }

    function bang() external pure {
        revert("bang");
    }

    receive() external payable {}
}

/// @dev Behaviour tests for the ERC-4337 `executeBatch(Call[])` override.
///      Guarded by `onlyEntryPoint`. Pays the execute fee before forwarding to
///      Solady's inner `executeBatch` which loops through each call in sequence
///      and reverts the entire batch if any call reverts.
contract WOTSPlusImplementation_executeBatch is WOTSPlusImplementationTest {
    BatchTarget internal target;
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public override {
        super.setUp();
        target = new BatchTarget();
        vm.deal(ENTRY_POINT, 10 ether);
    }

    function test_executeBatch_runsAllCallsInOrder() public {
        ERC4337.Call[] memory calls = new ERC4337.Call[](3);
        for (uint256 i = 0; i < 3; i++) {
            calls[i] = ERC4337.Call({
                target: address(target), value: 0, data: abi.encodeWithSelector(BatchTarget.inc.selector)
            });
        }

        vm.prank(ENTRY_POINT);
        wallet.executeBatch(calls);

        assertEq(target.count(), 3);
    }

    function test_executeBatch_forwardsValueToEachCall() public {
        ERC4337.Call[] memory calls = new ERC4337.Call[](2);
        calls[0] = ERC4337.Call({target: address(target), value: 0.01 ether, data: ""});
        calls[1] = ERC4337.Call({target: address(target), value: 0.02 ether, data: ""});

        uint256 targetBefore = address(target).balance;
        vm.prank(ENTRY_POINT);
        wallet.executeBatch(calls);

        assertEq(address(target).balance, targetBefore + 0.03 ether);
    }

    function test_executeBatch_collectsExecuteFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        ERC4337.Call[] memory calls = new ERC4337.Call[](1);
        calls[0] =
            ERC4337.Call({target: address(target), value: 0, data: abi.encodeWithSelector(BatchTarget.inc.selector)});

        uint256 walletBefore = address(wallet).balance;
        uint256 factoryBefore = address(factory).balance;

        vm.prank(ENTRY_POINT);
        wallet.executeBatch(calls);

        assertEq(address(wallet).balance, walletBefore - EXECUTE_FEE);
        assertEq(address(factory).balance, factoryBefore + EXECUTE_FEE);
    }

    function test_executeBatch_emptyBatchIsNoop() public {
        ERC4337.Call[] memory calls = new ERC4337.Call[](0);
        vm.prank(ENTRY_POINT);
        wallet.executeBatch(calls);

        assertEq(target.count(), 0);
    }

    function test_executeBatch_revertsWhen_callerNotEntryPoint() public {
        ERC4337.Call[] memory calls = new ERC4337.Call[](1);
        calls[0] =
            ERC4337.Call({target: address(target), value: 0, data: abi.encodeWithSelector(BatchTarget.inc.selector)});

        vm.prank(ALICE);
        vm.expectRevert(); // Solady Unauthorized
        wallet.executeBatch(calls);
    }

    // Whole batch reverts when any inner call reverts — no partial state.
    function test_executeBatch_revertsWhen_anyCallReverts() public {
        ERC4337.Call[] memory calls = new ERC4337.Call[](3);
        calls[0] =
            ERC4337.Call({target: address(target), value: 0, data: abi.encodeWithSelector(BatchTarget.inc.selector)});
        calls[1] =
            ERC4337.Call({target: address(target), value: 0, data: abi.encodeWithSelector(BatchTarget.bang.selector)});
        calls[2] =
            ERC4337.Call({target: address(target), value: 0, data: abi.encodeWithSelector(BatchTarget.inc.selector)});

        vm.prank(ENTRY_POINT);
        vm.expectRevert(bytes("bang"));
        wallet.executeBatch(calls);

        // Confirm the first `inc` was rolled back — state change is atomic.
        assertEq(target.count(), 0);
    }
}
