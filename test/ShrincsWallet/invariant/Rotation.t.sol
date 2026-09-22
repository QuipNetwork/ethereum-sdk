// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletRotationHandler} from "./RotationHandler.t.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";

/// forge-config: default.invariant.runs = 8
/// forge-config: default.invariant.depth = 16

/// @title ShrincsWallet — Rotation Invariant Suite (valid-signature chain)
/// @dev Stateful fuzz over the stateful `rotateKey` valid path. The suite
///      pre-generates a keychain and pre-signs a CHAIN of rotations — entry
///      `k` moves the bundle of key `k` to the fresh stateful tree of key
///      `k + 1` (stateless half carried forward), bound to action nonce `k`
///      at epoch `k` and authorized at a fresh leaf of key `k`'s tree. Fuzzed
///      replay order then explores every interleaving: entry `k` lands if
///      and only if entries `0..k-1` already did, so successes always form
///      the prefix `{0..m-1}`. The nonce, epoch, installed-commitment, and
///      spent-tree invariants replay that prefix off the handler mirror.
///      Stale replays revert with `InvalidSignature` only — a landed rotation
///      resets the epoch bitmap and installs a new commitment, so duplicates
///      can never reach the used-leaf guard (contrast the execute chain,
///      where duplicates pin `StaleStatefulLeaf`). Any other revert reason
///      fails `invariant_noBadReason`.
contract ShrincsWallet_Rotation_Invariant is ShrincsWalletTest {
    uint256 internal constant CHAIN_LEN = 3;

    ShrincsWalletRotationHandler public rotHandler;
    uint256 internal rotInitialNonce;

    /// @dev Public-key bundle of keychain key `k`: its own stateful tree,
    ///      the installed stateless half carried forward. Key 0 is the
    ///      installed main bundle exactly.
    function _chainBundle(uint256 k) internal view returns (SHRINCS.PublicKey memory pk) {
        if (k == 0) return _mainPk();
        (, SHRINCS.PublicKey memory fresh, bool ok) = _chainKey(k);
        require(ok, "chain keygen");
        pk.statefulPublicKey = fresh.statefulPublicKey;
        pk.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(fresh.statefulPublicKey, mainPk.pkSeed, mainPk.hypertreeRoot)
        );
        pk.pkSeed = mainPk.pkSeed;
        pk.hypertreeRoot = mainPk.hypertreeRoot;
    }

    function _chainKey(uint256 k)
        internal
        view
        returns (SHRINCS.SigningKey memory key, SHRINCS.PublicKey memory pk, bool ok)
    {
        if (k == 0) return (mainKey, mainPk, true);
        return SHRINCSTestSigner.keygen(abi.encodePacked("rotation-chain-key-", k), MAX_SIG);
    }

    function _chainCommitment(uint256 k) internal view returns (bytes32) {
        return _commitment32(_chainBundle(k));
    }

    /// @dev Signs entry `k`: ROTATE_KEY over the next commitment, bound to
    ///      action nonce `rotInitialNonce + k` at epoch `k`, authorized with
    ///      key `k` at a fresh leaf of its tree.
    function _signRotationEntry(uint256 k) internal view returns (SHRINCS.Signature memory) {
        bytes32 payloadHash = Codec.rotateKeyPayloadHash(_chainCommitment(k + 1));
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            rotInitialNonce + k,
            k,
            Codec.ACTION_ROTATE_KEY,
            payloadHash
        );
        (SHRINCS.SigningKey memory key, , bool ok) = _chainKey(k);
        require(ok, "chain signing keygen");
        bytes32 commitment = _chainCommitment(k);
        return _signStatefulActionWith(key, commitment, ctx, SIGN_BASE + 1);
    }

    function setUp() public override {
        super.setUp();
        rotInitialNonce = wallet.actionNonce();
        rotHandler = new ShrincsWalletRotationHandler();
        rotHandler.initialize(wallet, OWNER);
        for (uint256 k = 0; k < CHAIN_LEN; k++) {
            SHRINCS.PublicKey memory pk = _chainBundle(k);
            bytes32 nextCommitment = _chainCommitment(k + 1);
            (, SHRINCS.PublicKey memory next, bool nextOk) = _chainKey(k + 1);
            require(nextOk, "chain next keygen");
            rotHandler.pushValidRotation(
                pk,
                _signRotationEntry(k),
                SHRINCS.StatefulRotationTarget({
                    statefulPublicKey: next.statefulPublicKey,
                    publicKeyCommitment: abi.encodePacked(nextCommitment)
                }),
                nextCommitment,
                _treeId(next.statefulPublicKey)
            );
        }
        // Seeded prefix: land entry 0, then replay it for the deterministic
        // stale (a duplicate past the epoch reset reports InvalidSignature).
        // The remaining chain stays aligned — entry k binds (nonce k, epoch
        // k) — and the suite is never vacuous: a mutant that breaks all
        // landings fails `test_setUp` instead of passing on an empty mirror.
        rotHandler.fuzzRotateReplay(0);
        rotHandler.fuzzRotateReplay(0);
        targetContract(address(rotHandler));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = ShrincsWalletRotationHandler.fuzzRotateReplay.selector;
        targetSelector(FuzzSelector({addr: address(rotHandler), selectors: selectors}));
    }

    function test_setUp() public view override {
        assertEq(rotHandler.poolLength(), CHAIN_LEN, "rotation chain seeded");
        assertEq(rotHandler.callsRotate(), 1, "seeded entry landed");
        assertEq(rotHandler.staleCount(), 1, "seeded duplicate reported superseded nonce");
        assertEq(wallet.actionNonce(), rotInitialNonce + 1, "seeded landing advanced the nonce");
        assertEq(wallet.keyVersion(), 1, "seeded landing bumped the epoch");
        assertEq(wallet.getShrincsPublicKeyCommitment(), _chainCommitment(1), "seeded bundle installed");
        assertEq(wallet.statefulLeavesUsed(), 0, "seeded rotation reset the used counter");
    }

    /// @dev Every landing rotation advances the nonce by exactly one.
    function invariant_nonceTracksSuccesses() public view {
        assertEq(
            wallet.actionNonce(),
            rotInitialNonce + rotHandler.callsRotate(),
            "nonce diverged from rotation success count"
        );
    }

    /// @dev Every landing rotation bumps the epoch by exactly one, and
    ///      successes always form the prefix `{0..m-1}`.
    function invariant_epochTracksSuccesses() public view {
        uint256 m = rotHandler.successLength();
        assertEq(rotHandler.callsRotate(), m, "success mirror diverged from counter");
        assertEq(wallet.keyVersion(), m, "keyVersion diverged from rotation success count");
        for (uint256 i = 0; i < m; i++) {
            assertLt(rotHandler.successAt(i), m, "success outside the landed prefix");
        }
    }

    /// @dev The installed commitment is always the last landed entry's next
    ///      commitment — or the seed commitment when nothing landed.
    function invariant_commitmentTracksPrefix() public view {
        uint256 m = rotHandler.successLength();
        bytes32 expected = m == 0 ? mainCommitment : rotHandler.entryNextCommitment(m - 1);
        assertEq(wallet.getShrincsPublicKeyCommitment(), expected, "installed commitment left the landed prefix");
    }

    /// @dev Every landed rotation spends its next stateful tree exactly once.
    ///      The stateless half is carried forward, so it stays spent from
    ///      install throughout.
    function invariant_landedTreesSpent() public view {
        uint256 m = rotHandler.successLength();
        for (uint256 i = 0; i < m; i++) {
            assertTrue(
                wallet.harness_isStatefulTreeSpent(rotHandler.entryNextTreeId(rotHandler.successAt(i))),
                "landed rotation tree not marked spent"
            );
        }
        assertTrue(
            wallet.harness_isStatelessTreeSpent(_statelessId(mainPk)),
            "carried stateless tree left spent registry"
        );
    }

    /// @dev Each rotation resets the epoch leaf bitmap: the used counter is
    ///      zero whenever the last action was a rotation (or no action yet).
    function invariant_usedResetByRotation() public view {
        assertEq(wallet.statefulLeavesUsed(), 0, "used counter nonzero without a consuming non-rotation action");
    }

    /// @dev Stale replays must revert with one of the two guard-order
    ///      reasons. Any other reason — or a miscounted landing — fails here.
    function invariant_noBadReason() public view {
        assertEq(rotHandler.badReasonCount(), 0, "rotateKey reverted with an unexpected reason");
    }

    /// @dev Rotation touches neither ownership, the ERC-1271 bundle, nor the
    ///      factory linkage.
    function invariant_rotationTouchesNothingElse() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
        assertEq(wallet.getErc1271PublicKeyCommitment(), erc1271Commitment, "1271 commitment drifted");
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }
}
