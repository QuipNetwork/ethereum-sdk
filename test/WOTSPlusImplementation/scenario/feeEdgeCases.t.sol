// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

/// @title Fee Edge Case Tests
/// @dev Validates fee-related edge cases: fee changes between sign and execute,
///      zero fees, and fee accounting accuracy.
contract WOTSPlusImplementation_feeEdgeCases is WOTSPlusImplementationTest {
    /// @dev Admin raises execute fee after user signs but before execution.
    ///      The fee is committed in the signed digest, so changing it invalidates
    ///      the signature — preventing fee front-running.
    function test_feeEdgeCases_revertsWhen_executeFeeChangedBetweenSignAndExecute() public {
        // Set initial low fee
        vm.prank(ADMIN);
        factory.setExecuteFee(0.001 ether);

        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("fee-change-key");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, "", 0.001 ether);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        // Admin raises fee before Alice's tx lands
        vm.prank(ADMIN);
        factory.setExecuteFee(0.05 ether);

        // Execute reverts — signed fee (0.001) differs from on-chain fee (0.05)
        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, BOB, transferAmount, ""));
    }

    /// @dev When execute fee is 0, no ETH should be sent to the factory for calls.
    function test_feeEdgeCases_zeroExecuteFee() public {
        assertEq(factory.executeFee(), 0);

        DummyContract dummy = new DummyContract();
        bytes memory callData = abi.encodeWithSelector(DummyContract.setValueNoFee.selector, 42);
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("zero-fee-execute");

        bytes32 msgHash =
            _buildExecuteMessageHash(address(wallet), alicePubkey, nextPubkey, address(dummy), 0, callData, 0);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(alicePubkey, nextPubkey, sig, address(dummy), 0, callData));

        // No fee collected
        assertEq(address(factory).balance, factoryBalBefore);
        assertEq(dummy.value(), 42);
    }
}
