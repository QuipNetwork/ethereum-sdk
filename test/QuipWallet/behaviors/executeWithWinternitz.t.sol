// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet_executeWithWinternitz is QuipWalletTest {
    DummyContract public dummy;

    function setUp() public override {
        super.setUp();
        dummy = new DummyContract();
    }

    function test_executeWithWinternitz_executesCall() public {
        // Set execute fee
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 value = 42;
        uint256 requiredEth = 0.01 ether;
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValue.selector,
            value
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.executeWithWinternitz{value: EXECUTE_FEE + requiredEth}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        assertEq(dummy.value(), value);
    }

    function test_executeWithWinternitz_revertsWhen_targetReverts() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.failingFunction.selector
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert("Function always fails");
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_noFeeCall() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 noFeeValue = 84;
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            noFeeValue
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        assertEq(dummy.value(), noFeeValue);
    }

    function test_executeWithWinternitz_revertsWhen_insufficientFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert("Insufficient fee");
        wallet.executeWithWinternitz{value: 0}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_revertsWhen_callerNotOwner() public {
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert("You aren't the owner");
        wallet.executeWithWinternitz(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }
}
