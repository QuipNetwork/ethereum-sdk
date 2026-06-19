// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
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
///      Access control, the pre-verify leaf guards, and the `InvalidSignature` branch are testable
///      now. The empty-call (LeafConsumedOnly), fee-binding, ETH-transfer, and contract-call paths are
///      each exercised by a committed EXECUTE vector (`execute` / `executeEth` / `executeCall`).
contract ShrincsWallet_execute is ShrincsWalletTest {
    address internal constant TARGET = address(0xBEEF);

    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".mainKey");
    }

    function test_execute_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(_pk(), _statefulSigWithLeaf(1), TARGET, 0, "");
    }

    function test_execute_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.execute(_pk(), _statefulSigWithLeaf(0), TARGET, 0, "");
    }

    function test_execute_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.execute(_pk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), TARGET, 0, "");
    }

    function test_execute_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.execute(_pk(), _statefulSigWithLeaf(1), TARGET, 0, "");
    }

    function test_execute_revertsWhen_invalidSignature() public {
        // Leaf-1 sig that reaches verification but is bound to the ERC-4337 context, not EXECUTE.
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_pk(), _wrongContextStatefulSig(), TARGET, 0, "");
        // The leaf must NOT be consumed on a failed verification.
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf not consumed on invalid signature");
    }

    function test_execute_leafConsumedOnly() public {
        // The committed EXECUTE vector binds (TARGET=0xBEEF, value 0, empty data, fee 0); with an
        // empty call the wallet consumes the leaf and emits `LeafConsumedOnly` without interacting.
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.execute.signature");
        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.LeafConsumedOnly(1);
        vm.prank(OWNER);
        wallet.execute(_pk(), sig, TARGET, 0, "");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
    }

    function test_execute_feeBinding() public {
        // The EXECUTE vector binds fee 0 into the payload; a non-zero factory fee flips the bound
        // payload so the signature no longer verifies (InvalidSignature), and the leaf is preserved.
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.execute.signature");
        factory.setExecuteFee(999);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_pk(), sig, TARGET, 0, "");
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf not consumed on invalid signature");
    }

    function test_execute_transfersEth() public {
        // The `executeEth` vector binds (TARGET=0xBEEF, value 1 ether, empty data, fee 0).
        vm.deal(WALLET, 1 ether);
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.executeEth.signature");
        uint256 targetBefore = TARGET.balance;

        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.ExecutionSucceeded(TARGET, 1 ether, keccak256(""));
        vm.prank(OWNER);
        wallet.execute(_pk(), sig, TARGET, 1 ether, "");

        assertEq(TARGET.balance - targetBefore, 1 ether, "ETH delivered to target");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
    }

    function test_execute_callsContract() public {
        // The `executeCall` vector binds (target=0xCA11, value 0, data 0x1234). Etch a callee with
        // code at that address so the real `LibCall.callContract` interaction lands.
        address callee = address(0xCA11);
        vm.etch(callee, address(new MockCallee()).code);
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.executeCall.signature");

        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.ExecutionSucceeded(callee, 0, keccak256(hex"1234"));
        vm.prank(OWNER);
        wallet.execute(_pk(), sig, callee, 0, hex"1234");

        assertTrue(MockCallee(callee).called(), "callee received the call");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
    }
}
