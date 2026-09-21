// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletExecuteHandler} from "./ExecuteHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 32

/// @title ShrincsWallet — Execute Invariant Suite (valid-signature chain)
/// @dev Stateful fuzz over the owner `execute` valid path. The suite
///      pre-signs a CHAIN of authorizations — entry `k` binds action nonce
///      `k` — then fuzzes replay order. Entry `k` lands if and only if
///      entries `0..k-1` already did, so successes always form the prefix
///      `{0..m-1}`: the nonce, leaf bitmap, and ETH accounting invariants
///      replay that prefix off the handler mirror. Out-of-order replays are
///      stale by construction (`InvalidSignature`); duplicates of a consumed
///      entry revert with `StaleStatefulLeaf`, pinning the wallet's guard
///      order (used-leaf check before signature verification). Any other
///      revert reason fails `invariant_noBadReason`.
///
///      The factory execute fee stays at its setUp default (0): fee
///      charging is covered by per-function behavior tests, and a zero fee
///      keeps the wallet-balance accounting exact.
contract ShrincsWallet_Execute_Invariant is ShrincsWalletTest {
    uint256 internal constant CHAIN_LEN = 5;
    uint256 internal constant WALLET_FUNDS = 10 ether;

    ShrincsWalletExecuteHandler public execHandler;
    uint256 internal execInitialNonce;

    function _chainSink(uint256 k) internal pure returns (address) {
        return address(uint160(0xE000 + k));
    }

    function _chainValue(uint256 k) internal pure returns (uint256) {
        return 0.1 ether * (k + 1);
    }

    /// @dev Signs entry `k` of the chain: EXECUTE over (sink, value, empty
    ///      data, maxFee 0) bound to action nonce `k` at epoch 0, authorized
    ///      at leaf `SIGN_BASE + 1 + k`. Explicit-nonce signing (no live
    ///      execution between entries) is what makes the chain a chain.
    function _signChainEntry(uint256 k) internal view returns (SHRINCS.Signature memory) {
        address target = _chainSink(k);
        uint256 value = _chainValue(k);
        bytes32 payloadHash = Codec.executePayloadHash(target, value, keccak256(""), 0);
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            execInitialNonce + k,
            0,
            Codec.ACTION_EXECUTE,
            payloadHash
        );
        return _signStatefulActionWith(mainKey, mainCommitment, ctx, SIGN_BASE + 1 + uint32(k));
    }

    function setUp() public override {
        super.setUp();
        execInitialNonce = wallet.actionNonce();
        execHandler = new ShrincsWalletExecuteHandler();
        execHandler.initialize(wallet, OWNER);
        vm.deal(WALLET, WALLET_FUNDS);
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            execHandler.pushValidExecute(
                _mainPk(),
                _signChainEntry(k),
                _chainSink(k),
                _chainValue(k),
                "",
                0,
                SIGN_BASE + 1 + uint32(k)
            );
        }
        targetContract(address(execHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletExecuteHandler.fuzzExecuteReplay.selector;
        targetSelector(FuzzSelector({addr: address(execHandler), selectors: selectors}));
    }

    function test_setUp() public view override {
        assertEq(execHandler.poolLength(), CHAIN_LEN, "execute chain seeded");
        assertEq(wallet.actionNonce(), execInitialNonce, "nonce untouched by seeding");
        assertEq(wallet.statefulLeavesUsed(), 0, "no leaf consumed by seeding");
        assertEq(WALLET.balance, WALLET_FUNDS, "wallet funded");
    }

    /// @dev Every landing entry advances the nonce by exactly one, so the
    ///      success count equals the nonce delta — no more, no less.
    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            execInitialNonce + execHandler.callsExecute(),
            "nonce diverged from execute success count"
        );
    }

    /// @dev Successes always form the prefix `{0..m-1}`: each recorded index
    ///      lies below the success count, and the used-leaf counter matches
    ///      it (one fresh leaf per landing entry).
    function invariant_successesFormPrefix() public view {
        uint256 m = execHandler.successLength();
        assertEq(m, execHandler.callsExecute(), "success mirror diverged from counter");
        assertEq(wallet.statefulLeavesUsed(), m, "used counter diverged from success count");
        for (uint256 i = 0; i < m; i++) {
            uint256 idx = execHandler.successAt(i);
            assertLt(idx, m, "success outside the landed prefix");
            assertTrue(wallet.isStatefulLeafUsed(execHandler.entryLeaf(idx)), "landed entry leaf not marked");
        }
    }

    /// @dev ETH accounting: the wallet retains exactly funds minus the
    ///      landed prefix's values, and each sink holds its value if and
    ///      only if its entry landed.
    function invariant_ethAccountingExact() public view {
        uint256 m = execHandler.successLength();
        uint256 spent;
        for (uint256 i = 0; i < m; i++) {
            spent += execHandler.entryValue(execHandler.successAt(i));
        }
        assertEq(WALLET.balance, WALLET_FUNDS - spent, "wallet balance diverged from landed values");
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            uint256 expected = k < m ? execHandler.entryValue(k) : 0;
            assertEq(_chainSink(k).balance, expected, "sink balance diverged from landed prefix");
        }
    }

    /// @dev Stale replays (out-of-order or duplicate) must revert with
    ///      `InvalidSignature`. Any other reason — or a landing entry that
    ///      was never counted — fails here.
    function invariant_noBadReason() public view {
        assertEq(execHandler.badReasonCount(), 0, "execute reverted with an unexpected reason");
    }

    /// @dev Execute touches neither ownership, epoch, commitments, nor the
    ///      spent-tree registry.
    function invariant_executeTouchesNothingElse() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
        assertEq(wallet.keyVersion(), 0, "keyVersion advanced without rotation");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment, "main commitment drifted");
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }
}
