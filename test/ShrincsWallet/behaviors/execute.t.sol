// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Records that it received a call (used to prove the contract-call execution path ran).
contract MockCallee {
    bool public called;

    fallback() external {
        called = true;
    }
}

/// @dev Behavior tests for the owner-path `execute(PublicKey,StatefulSignature,address,uint256,bytes)`.
///      Access control, the pre-verify leaf guards, the `InvalidSignature` branch, and the
///      empty-call (LeafConsumedOnly), fee-binding, ETH-transfer, and contract-call paths are each
///      exercised with live-signed EXECUTE signatures.
contract ShrincsWallet_execute is ShrincsWalletTest {
    address internal constant TARGET = address(0xBEEF);

    /// @dev Signs the wallet's EXECUTE context over (target, value, data, live fee) at `leaf`.
    function _executeSig(address target, uint256 value, bytes memory data, uint32 leaf)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory)
    {
        bytes32 payloadHash =
            Codec.executePayloadHash(target, value, keccak256(data), wallet.getExecuteFee());
        return _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, leaf);
    }

    function test_execute_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(1), TARGET, 0, "");
    }

    function test_execute_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(0), TARGET, 0, "");
    }

    function test_execute_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), TARGET, 0, "");
    }

    function test_execute_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(1), TARGET, 0, "");
    }

    function test_execute_revertsWhen_invalidSignature() public {
        // Leaf-1 sig that reaches verification but is bound to the ERC-4337 context, not EXECUTE.
        ShrincsTypes.StatefulSignature memory sig = _wrongContextStatefulSig();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_mainPk(), sig, TARGET, 0, "");
        // The leaf must NOT be consumed on a failed verification.
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf not consumed on invalid signature");
    }

    function test_execute_leafConsumedOnly() public {
        // A signature binding (TARGET, value 0, empty data, fee 0); with an empty call the wallet
        // consumes the leaf and emits `LeafConsumedOnly` without interacting.
        ShrincsTypes.StatefulSignature memory sig = _executeSig(TARGET, 0, "", 1);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.LeafConsumedOnly(1);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, 0, "");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
    }

    function test_execute_feeBinding() public {
        // The signature binds fee 0 into the payload; a non-zero factory fee flips the bound
        // payload so the signature no longer verifies (InvalidSignature), and the leaf is preserved.
        ShrincsTypes.StatefulSignature memory sig = _executeSig(TARGET, 0, "", 1);
        factory.setExecuteFee(999);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_mainPk(), sig, TARGET, 0, "");
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf not consumed on invalid signature");
    }

    function test_execute_transfersEth() public {
        vm.deal(WALLET, 1 ether);
        ShrincsTypes.StatefulSignature memory sig = _executeSig(TARGET, 1 ether, "", 1);
        uint256 targetBefore = TARGET.balance;

        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.ExecutionSucceeded(TARGET, 1 ether, keccak256(""));
        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, 1 ether, "");

        assertEq(TARGET.balance - targetBefore, 1 ether, "ETH delivered to target");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
    }

    function test_execute_callsContract() public {
        // Etch a callee with code so the real `LibCall.callContract` interaction lands.
        address callee = address(0xCA11);
        vm.etch(callee, address(new MockCallee()).code);
        ShrincsTypes.StatefulSignature memory sig = _executeSig(callee, 0, hex"1234", 1);

        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.ExecutionSucceeded(callee, 0, keccak256(hex"1234"));
        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, callee, 0, hex"1234");

        assertTrue(MockCallee(callee).called(), "callee received the call");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
    }
}
