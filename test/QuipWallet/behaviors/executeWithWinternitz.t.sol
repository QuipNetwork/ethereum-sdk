// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

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
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
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

    function test_executeWithWinternitz_zeroValueForwardedToTarget() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 noFeeValue = 84;
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            noFeeValue
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
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

    function test_executeWithWinternitz_rotatesPqOwner() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey, bytes32 nextPrivateKey) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        // First call succeeds and rotates the pq owner
        vm.prank(ALICE);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        // Attempting to use the old alicePrivateKey should now fail
        (WOTSPlus.WinternitzAddress memory nextPubkey2,) = _generateKeyPair("next-key-2");
        bytes memory callData2 = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            99
        );

        // Sign with old alicePrivateKey against the NEW current pq owner (nextPubkey)
        bytes32 msgHash2 = _buildExecuteMessageHash(
            address(wallet), nextPubkey, nextPubkey2, address(dummy), callData2
        );
        WOTSPlus.WinternitzElements memory sig2 = _sign(alicePrivateKey, msgHash2);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey2,
            sig2,
            payable(address(dummy)),
            callData2
        );

        // But signing with the new key should work
        WOTSPlus.WinternitzElements memory sig3 = _sign(nextPrivateKey, msgHash2);

        vm.prank(ALICE);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey2,
            sig3,
            payable(address(dummy)),
            callData2
        );

        assertEq(dummy.value(), 99);
    }

    function test_executeWithWinternitz_forwardsValueMinusFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 extraValue = 0.05 ether;
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValue.selector,
            99
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 dummyBalBefore = address(dummy).balance;

        vm.prank(ALICE);
        wallet.executeWithWinternitz{value: EXECUTE_FEE + extraValue}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        assertEq(address(dummy).balance, dummyBalBefore + extraValue);
        assertEq(dummy.value(), 99);
    }

    function test_executeWithWinternitz_forwardsZeroWhenMsgValueEqualsFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            55
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 dummyBalBefore = address(dummy).balance;

        vm.prank(ALICE);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        assertEq(address(dummy).balance, dummyBalBefore);
        assertEq(dummy.value(), 55);
    }

    function test_executeWithWinternitz_forwardsZeroWhenNoMsgValue() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            77
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 walletBalBefore = address(wallet).balance;
        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.executeWithWinternitz(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        assertEq(address(wallet).balance, walletBalBefore - EXECUTE_FEE);
        assertEq(address(factory).balance, factoryBalBefore + EXECUTE_FEE);
        assertEq(dummy.value(), 77);
    }

    function test_executeWithWinternitz_returnsCallData() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            123
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        bytes memory returnData = wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );

        assertEq(returnData.length, 0);
        assertEq(dummy.value(), 123);
    }

    function test_executeWithWinternitz_revertsWhen_targetReverts() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.failingFunction.selector
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(DummyContract.AlwaysFails.selector);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_revertsWhen_insufficientBalance() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        // Drain wallet so balance cannot cover the fee
        deal(address(wallet), 0);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(IQuipWallet.InsufficientBalance.selector, EXECUTE_FEE, 0));
        wallet.executeWithWinternitz(
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
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.executeWithWinternitz(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_revertsWhen_nextPqOwnerSeedIsZero() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        WOTSPlus.WinternitzAddress memory nextPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_revertsWhen_nextPqOwnerHashIsZero() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        WOTSPlus.WinternitzAddress memory nextPubkey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_revertsWhen_invalidSignature() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        // Sign with a wrong key (BOB's key instead of ALICE's)
        (, bytes32 wrongPrivateKey) = _generateKeyPair("wrong-key");
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(wrongPrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.executeWithWinternitz{value: EXECUTE_FEE}(
            nextPubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }

    function test_executeWithWinternitz_revertsWhen_pqOwnerReuse() public {
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector,
            42
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, alicePubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.executeWithWinternitz(
            alicePubkey,
            sig,
            payable(address(dummy)),
            callData
        );
    }
}
