// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";

/// @dev Behaviour tests for `_collectExecuteFee()`.
///      Pulls `getExecuteFee()` wei from the wallet and forwards to the factory.
///      No-op when the fee is zero; reverts via `safeTransferETH` if the
///      wallet cannot cover the fee.
contract WOTSPlusImplementation__collectExecuteFee is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-cef");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr =
            factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-cef-vault"), payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function test_exposed_collectExecuteFee_feeZeroIsNoop() public {
        uint256 walletBefore = address(harnessProxy).balance;
        uint256 factoryBefore = address(factory).balance;

        // Default fee is zero.
        harnessProxy.exposed_collectExecuteFee();

        assertEq(address(harnessProxy).balance, walletBefore);
        assertEq(address(factory).balance, factoryBefore);
    }

    function test_exposed_collectExecuteFee_transfersWhenAffordable() public {
        uint256 fee = EXECUTE_FEE;
        vm.prank(ADMIN);
        factory.setExecuteFee(fee);

        uint256 walletBefore = address(harnessProxy).balance;
        uint256 factoryBefore = address(factory).balance;

        harnessProxy.exposed_collectExecuteFee();

        assertEq(address(harnessProxy).balance, walletBefore - fee);
        assertEq(address(factory).balance, factoryBefore + fee);
    }

    function test_exposed_collectExecuteFee_revertsWhen_walletShortFunded() public {
        // Fee > wallet balance: collection must revert via SafeTransferLib.
        // Factory enforces `fee <= MAX_FEE`, so we drain the wallet below MAX_FEE
        // rather than raising the fee above the wallet balance.
        uint256 fee = factory.MAX_FEE();
        vm.prank(ADMIN);
        factory.setExecuteFee(fee);

        vm.deal(address(harnessProxy), fee - 1);

        vm.expectRevert(SafeTransferLib.ETHTransferFailed.selector);
        harnessProxy.exposed_collectExecuteFee();
    }

    // Boundary: balance == fee. Should transfer exactly fee wei, leaving 0 behind.
    function test_exposed_collectExecuteFee_boundary_balanceEqualsFee() public {
        uint256 fee = factory.MAX_FEE();
        vm.prank(ADMIN);
        factory.setExecuteFee(fee);

        // Set wallet balance to exactly the fee.
        vm.deal(address(harnessProxy), fee);

        uint256 factoryBefore = address(factory).balance;
        harnessProxy.exposed_collectExecuteFee();
        assertEq(address(harnessProxy).balance, 0);
        assertEq(address(factory).balance, factoryBefore + fee);
    }
}
