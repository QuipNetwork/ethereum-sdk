// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletValidationHandler} from "./ValidationHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 32

/// @title ShrincsWallet — Validation Invariant Suite (bundler userOp chain)
/// @dev Stateful fuzz over the ERC-4337 validation valid path — the
///      bundler's view. The suite pre-signs a CHAIN of userOps (hybrid blobs:
///      SHRINCS signature plus owner ECDSA co-signature), entry `k` bound to
///      wrapper nonce `k`, then fuzzes submission order. Entry `k` validates
///      if and only if entries `0..k-1` already did, so successes always form
///      the prefix `{0..m-1}`: the nonce, leaf bitmap, and stale-reason
///      invariants replay that prefix off the handler mirror.
///
///      Validation soft-fails (returns 1) instead of reverting: out-of-order
///      submissions report `InvalidSignature`, duplicates of a consumed leaf
///      report `StaleStatefulLeaf` — the same guard order as the owner
///      execute path. Any other reason fails `invariant_noBadReason`.
contract ShrincsWallet_Validation_Invariant is ShrincsWalletTest {
    uint256 internal constant CHAIN_LEN = 5;

    ShrincsWalletValidationHandler public valHandler;
    uint256 internal valInitialNonce;

    function _chainHash(uint256 k) internal pure returns (bytes32) {
        return keccak256(abi.encode("validation-chain", k));
    }

    /// @dev Signs entry `k`: ERC4337_EXECUTE over the op hash bound to
    ///      wrapper nonce `k` at epoch 0, authorized at leaf
    ///      `SIGN_BASE + 1 + k`, co-signed by the owner.
    function _signChainOp(uint256 k) internal view returns (ERC4337.PackedUserOperation memory op) {
        bytes32 userOpHash = _chainHash(k);
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            valInitialNonce + k,
            0,
            Codec.ACTION_ERC4337_EXECUTE,
            Codec.erc4337PayloadHash(userOpHash)
        );
        SHRINCS.Signature memory sig =
            _signStatefulActionWith(mainKey, mainCommitment, ctx, SIGN_BASE + 1 + uint32(k));
        op = _makeUserOp(_userOpBlob(sig, userOpHash));
    }

    function setUp() public override {
        super.setUp();
        valInitialNonce = wallet.actionNonce();
        valHandler = new ShrincsWalletValidationHandler();
        valHandler.initialize(wallet);
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            ERC4337.PackedUserOperation memory op = _signChainOp(k);
            valHandler.pushValidOp(op, _chainHash(k), SIGN_BASE + 1 + uint32(k));
        }
        targetContract(address(valHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletValidationHandler.fuzzValidateReplay.selector;
        targetSelector(FuzzSelector({addr: address(valHandler), selectors: selectors}));
    }

    function test_setUp() public view override {
        assertEq(valHandler.poolLength(), CHAIN_LEN, "validation chain seeded");
        assertEq(wallet.actionNonce(), valInitialNonce, "nonce untouched by seeding");
        assertEq(wallet.statefulLeavesUsed(), 0, "no leaf consumed by seeding");
    }

    /// @dev Every validated op advances the wrapper nonce by exactly one.
    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            valInitialNonce + valHandler.callsValidate(),
            "nonce diverged from validation success count"
        );
    }

    /// @dev Successes always form the prefix `{0..m-1}`: each recorded index
    ///      lies below the success count, and the used-leaf counter matches
    ///      it (one fresh leaf per validated op).
    function invariant_successesFormPrefix() public view {
        uint256 m = valHandler.successLength();
        assertEq(m, valHandler.callsValidate(), "success mirror diverged from counter");
        assertEq(wallet.statefulLeavesUsed(), m, "used counter diverged from success count");
        for (uint256 i = 0; i < m; i++) {
            uint256 idx = valHandler.successAt(i);
            assertLt(idx, m, "success outside the landed prefix");
            assertTrue(wallet.isStatefulLeafUsed(valHandler.entryLeaf(idx)), "landed entry leaf not marked");
        }
    }

    /// @dev Stale submissions must report one of the two guard-order
    ///      reasons. Any other reason fails here.
    function invariant_noBadReason() public view {
        assertEq(valHandler.badReasonCount(), 0, "validation reported an unexpected reason");
    }

    /// @dev Validation touches neither ownership, epoch, commitments, nor
    ///      the spent-tree registry.
    function invariant_validationTouchesNothingElse() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
        assertEq(wallet.keyVersion(), 0, "keyVersion advanced without rotation");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment, "main commitment drifted");
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }
}
