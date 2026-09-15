// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Records that it received a call (used to prove the contract-call execution path ran).
contract MockCallee {
    bool public called;

    fallback() external payable {
        called = true;
    }
}

/// @dev Behavior tests for the owner-path
///      `execute(PublicKey,StatefulSignature,address,uint256,bytes,uint256 maxFee)`.
///      Access control, the pre-verify leaf guards, the `InvalidSignature` branch, and the
///      empty-call (LeafConsumedOnly), maxFee-cap, ETH-transfer, and contract-call paths are each
///      exercised with live-signed EXECUTE signatures.
contract ShrincsWallet_execute is ShrincsWalletTest {
    address internal constant TARGET = address(0xBEEF);

    /// @dev Signs the wallet's EXECUTE context over (target, value, data, maxFee) at `leaf`.
    ///      `maxFee` is the signer's fee CEILING — execution charges the live factory fee and
    ///      reverts only if it exceeds this cap.
    function _executeSig(address target, uint256 value, bytes memory data, uint32 leaf, uint256 maxFee)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        bytes32 payloadHash = Codec.executePayloadHash(target, value, keccak256(data), maxFee);
        return _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, leaf);
    }

    /// @dev Convenience overload binding maxFee 0 (the setUp factory default).
    function _executeSig(address target, uint256 value, bytes memory data, uint32 leaf)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        return _executeSig(target, value, data, leaf, 0);
    }

    function test_execute_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), TARGET, 0, "", 0);
    }

    function test_execute_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(0), TARGET, 0, "", 0);
    }

    function test_execute_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), TARGET, 0, "", 0);
    }

    function test_execute_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.execute(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), TARGET, 0, "", 0);
    }

    function test_execute_revertsWhen_invalidSignature() public {
        // Leaf-1 sig that reaches verification but is bound to the ERC-4337 context, not EXECUTE.
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_mainPk(), sig, TARGET, 0, "", 0);
        // The leaf must NOT be consumed on a failed verification.
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on invalid signature");
    }

    function test_execute_leafAndNonceConsumedOnly() public {
        // A signature binding (TARGET, value 0, empty data, maxFee 0); with an empty call the wallet
        // consumes the leaf and emits `LeafConsumedOnly` without interacting. Because the nonce
        // advances too, this empty-execute path doubles as the one-leaf cancel-all for every
        // outstanding signed authorization.
        SHRINCS.Signature memory sig = _executeSig(TARGET, 0, "", 1);
        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.LeafConsumedOnly(SIGN_BASE + 1);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, 0, "", 0);
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 consumed");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the action nonce");
    }

    /// @dev Supersession headline: a signature bound to a superseded nonce is dead even though
    ///      its leaf is unused and its payload is intact.
    function test_execute_revertsWhen_staleNonce() public {
        // Sign at the live nonce, then let ANOTHER action land (leaf 2), advancing the nonce.
        SHRINCS.Signature memory stale = _executeSig(TARGET, 0, "", 1);
        SHRINCS.Signature memory fresh = _executeSig(TARGET, 0, "", 2);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), fresh, TARGET, 0, "", 0);
        assertEq(wallet.actionNonce(), 1, "interleaved action advanced the nonce");

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_mainPk(), stale, TARGET, 0, "", 0);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "superseded signature's leaf not consumed");
    }

    function test_execute_maxFeeBinding() public {
        // The signature binds maxFee 0 into the payload; presenting a different calldata maxFee
        // flips the bound payload so the signature no longer verifies (InvalidSignature) — a
        // relayer cannot raise the signer's ceiling. The leaf is preserved.
        SHRINCS.Signature memory sig = _executeSig(TARGET, 0, "", 1, 0);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.execute(_mainPk(), sig, TARGET, 0, "", 999);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on invalid signature");
    }

    /// @dev Cap matrix (up): a live fee raised past the signed ceiling reverts
    ///      `ExecuteFeeExceedsCap`. Unlike the 4337 path (where validation already consumed the
    ///      leaf), the direct path rolls the WHOLE call back — leaf and nonce included.
    function test_execute_revertsWhen_feeExceedsCap() public {
        SHRINCS.Signature memory sig = _executeSig(TARGET, 0, "", 1, 0);
        _setExecuteFee(999);
        vm.deal(WALLET, 1 ether);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.ExecuteFeeExceedsCap.selector, 999, 0));
        wallet.execute(_mainPk(), sig, TARGET, 0, "", 0);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf preserved by the full revert");
        assertEq(wallet.actionNonce(), 0, "nonce preserved by the full revert");
    }

    /// @dev Cap matrix (equal): live fee == maxFee succeeds and charges exactly the fee.
    function test_execute_liveFeeEqualsCap() public {
        _setExecuteFee(0.01 ether);
        vm.deal(WALLET, 1 ether);
        SHRINCS.Signature memory sig = _executeSig(TARGET, 0.5 ether, "", 1, 0.01 ether);
        uint256 factoryBefore = address(factory).balance;

        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, 0.5 ether, "", 0.01 ether);

        assertEq(address(factory).balance - factoryBefore, 0.01 ether, "exact fee charged");
        assertEq(TARGET.balance, 0.5 ether, "value delivered");
    }

    /// @dev Cap matrix (down): a fee DECREASE between signing and landing succeeds, charging the
    ///      lower live fee — the deliberate `<=` semantics (previously this was an
    ///      `InvalidSignature` digest mismatch that bricked the in-flight signature).
    function test_execute_feeDecreaseSucceedsChargingLiveFee() public {
        _setExecuteFee(0.01 ether);
        vm.deal(WALLET, 1 ether);
        SHRINCS.Signature memory sig = _executeSig(TARGET, 0.5 ether, "", 1, 0.01 ether);

        _setExecuteFee(0.002 ether); // fee lowered after signing
        uint256 factoryBefore = address(factory).balance;

        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, 0.5 ether, "", 0.01 ether);

        assertEq(address(factory).balance - factoryBefore, 0.002 ether, "LIVE fee charged, not the ceiling");
        assertEq(TARGET.balance, 0.5 ether, "value delivered");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf consumed");
    }

    function test_execute_transfersEth() public {
        vm.deal(WALLET, 1 ether);
        SHRINCS.Signature memory sig = _executeSig(TARGET, 1 ether, "", 1);
        uint256 targetBefore = TARGET.balance;

        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.ExecutionSucceeded(TARGET, 1 ether, keccak256(""));
        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, 1 ether, "", 0);

        assertEq(TARGET.balance - targetBefore, 1 ether, "ETH delivered to target");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 consumed");
    }

    function test_execute_callsContract() public {
        // Etch a callee with code so the real `LibCall.callContract` interaction lands.
        address callee = address(0xCA11);
        vm.etch(callee, address(new MockCallee()).code);
        SHRINCS.Signature memory sig = _executeSig(callee, 0, hex"1234", 1);

        vm.expectEmit(true, false, false, true, address(wallet));
        emit IShrincsWallet.ExecutionSucceeded(callee, 0, keccak256(hex"1234"));
        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, callee, 0, hex"1234", 0);

        assertTrue(MockCallee(payable(callee)).called(), "callee received the call");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 consumed");
    }

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    /*             VALUE ACCOUNTING (WALLET BALANCE)             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `msg.value == value`, plain ETH transfer (data.length == 0): the caller-attached
    ///      ETH funds the transfer, so the wallet's own balance is UNCHANGED.
    function test_execute_msgValueEqualsValue_ethTransfer_walletBalanceUnchanged() public {
        uint256 value = 0.7 ether;
        vm.deal(WALLET, 1 ether);
        vm.deal(OWNER, value);
        SHRINCS.Signature memory sig = _executeSig(TARGET, value, "", 1);
        uint256 walletBefore = WALLET.balance;
        uint256 targetBefore = TARGET.balance;
        uint256 ownerBefore = OWNER.balance;

        vm.prank(OWNER);
        wallet.execute{value: value}(_mainPk(), sig, TARGET, value, "", 0);

        assertEq(WALLET.balance, walletBefore, "wallet balance unchanged: msg.value funded the transfer");
        assertEq(TARGET.balance - targetBefore, value, "target received value");
        assertEq(ownerBefore - OWNER.balance, value, "caller's attached ETH was spent");
    }

    /// @dev `msg.value == 0`, `value > 0`, plain ETH transfer (data.length == 0): the transfer
    ///      is paid from the wallet's pre-funded reserves, so its balance drops by exactly `value`.
    function test_execute_zeroMsgValue_ethTransfer_walletBalanceDebited() public {
        uint256 value = 0.7 ether;
        vm.deal(WALLET, 1 ether);
        SHRINCS.Signature memory sig = _executeSig(TARGET, value, "", 1);
        uint256 walletBefore = WALLET.balance;
        uint256 targetBefore = TARGET.balance;

        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, TARGET, value, "", 0);

        assertEq(walletBefore - WALLET.balance, value, "wallet debited exactly value");
        assertEq(WALLET.balance, walletBefore - value, "wallet keeps the remainder");
        assertEq(TARGET.balance - targetBefore, value, "target received value");
    }

    /// @dev `msg.value == value`, contract call (data.length != 0): the caller-attached ETH
    ///      rides along with the call, so the wallet's own balance is UNCHANGED.
    function test_execute_msgValueEqualsValue_contractCall_walletBalanceUnchanged() public {
        uint256 value = 0.7 ether;
        address callee = address(0xCA11);
        vm.etch(callee, address(new MockCallee()).code);
        vm.deal(WALLET, 1 ether);
        vm.deal(OWNER, value);
        SHRINCS.Signature memory sig = _executeSig(callee, value, hex"1234", 1);
        uint256 walletBefore = WALLET.balance;
        uint256 calleeBefore = callee.balance;
        uint256 ownerBefore = OWNER.balance;

        vm.prank(OWNER);
        wallet.execute{value: value}(_mainPk(), sig, callee, value, hex"1234", 0);

        assertEq(WALLET.balance, walletBefore, "wallet balance unchanged: msg.value funded the call");
        assertEq(callee.balance - calleeBefore, value, "callee received value");
        assertEq(ownerBefore - OWNER.balance, value, "caller's attached ETH was spent");
        assertTrue(MockCallee(payable(callee)).called(), "callee received the call");
    }

    /// @dev `msg.value == 0`, `value > 0`, contract call (data.length != 0): the call's value is
    ///      paid from the wallet's pre-funded reserves, so its balance drops by exactly `value`.
    function test_execute_zeroMsgValue_contractCall_walletBalanceDebited() public {
        uint256 value = 0.7 ether;
        address callee = address(0xCA11);
        vm.etch(callee, address(new MockCallee()).code);
        vm.deal(WALLET, 1 ether);
        SHRINCS.Signature memory sig = _executeSig(callee, value, hex"1234", 1);
        uint256 walletBefore = WALLET.balance;
        uint256 calleeBefore = callee.balance;

        vm.prank(OWNER);
        wallet.execute(_mainPk(), sig, callee, value, hex"1234", 0);

        assertEq(walletBefore - WALLET.balance, value, "wallet debited exactly value");
        assertEq(WALLET.balance, walletBefore - value, "wallet keeps the remainder");
        assertEq(callee.balance - calleeBefore, value, "callee received value");
        assertTrue(MockCallee(payable(callee)).called(), "callee received the call");
    }
}
