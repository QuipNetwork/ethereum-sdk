// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";

/// @dev Inline target contract for execute-via-EntryPoint tests. `echo` returns
///      its input bytes so we can assert `execute` propagates returndata. The
///      revert variant is used to assert target-side reverts bubble up.
contract ExecuteTarget {
    event Called(uint256 value, bytes data);

    function echo(bytes calldata data) external payable returns (bytes memory) {
        emit Called(msg.value, data);
        return data;
    }

    function reverts() external pure {
        revert("nope");
    }

    receive() external payable {}
}

/// @dev Behaviour tests for the ERC-4337 `execute(address, uint256, bytes)`
///      override. Guarded by `onlyEntryPoint` (tighter than Solady's
///      `onlyEntryPointOrOwner`). Pays the execute fee via `_collectExecuteFee`
///      before forwarding to Solady's inner `execute`; reverts if the wallet
///      cannot cover the fee.
contract WOTSPlusImplementation_execute_erc4337 is WOTSPlusImplementationTest {
    ExecuteTarget internal target;

    address constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public override {
        super.setUp();
        target = new ExecuteTarget();
        vm.deal(ENTRY_POINT, 10 ether);
    }

    function test_execute_erc4337_transfersValue() public {
        uint256 sendValue = 0.1 ether;
        uint256 walletBefore = address(wallet).balance;
        uint256 targetBefore = address(target).balance;

        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), sendValue, "");

        assertEq(address(wallet).balance, walletBefore - sendValue);
        assertEq(address(target).balance, targetBefore + sendValue);
    }

    function test_execute_erc4337_forwardsCallAndReturnsData() public {
        bytes memory payload = abi.encodeWithSelector(
            ExecuteTarget.echo.selector,
            bytes("hello")
        );
        vm.prank(ENTRY_POINT);
        bytes memory ret = wallet.execute(address(target), 0, payload);

        // ret is the ABI-encoded bytes return of echo.
        bytes memory decoded = abi.decode(ret, (bytes));
        assertEq(string(decoded), "hello");
    }

    function test_execute_erc4337_collectsExecuteFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 walletBefore = address(wallet).balance;
        uint256 factoryBefore = address(factory).balance;

        vm.prank(ENTRY_POINT);
        wallet.execute(address(target), 0, "");

        assertEq(address(wallet).balance, walletBefore - EXECUTE_FEE);
        assertEq(address(factory).balance, factoryBefore + EXECUTE_FEE);
    }

    function test_execute_erc4337_revertsWhen_callerNotEntryPoint() public {
        vm.prank(ALICE);
        vm.expectRevert(); // Solady Unauthorized (selector 0x82b42900)
        wallet.execute(address(target), 0, "");
    }

    function test_execute_erc4337_revertsWhen_targetReverts() public {
        bytes memory payload = abi.encodeWithSelector(
            ExecuteTarget.reverts.selector
        );
        vm.prank(ENTRY_POINT);
        vm.expectRevert(bytes("nope"));
        wallet.execute(address(target), 0, payload);
    }

    // Fee collection is strict inside `_collectExecuteFee`: if the wallet
    // balance is below the fee at entry, execution reverts.
    function test_execute_erc4337_revertsWhen_balanceBelowFee() public {
        // Read first so `vm.prank` below is not consumed by the MAX_FEE() view call.
        uint256 maxFee = factory.MAX_FEE();
        vm.prank(ADMIN);
        factory.setExecuteFee(maxFee);

        vm.deal(address(wallet), maxFee - 1);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SafeTransferLib.ETHTransferFailed.selector);
        wallet.execute(address(target), 0, "");
    }
}
