// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWallet} from "../../contracts/shrincs/ShrincsWallet.sol";
import {ShrincsWalletStorage as Storage} from "../../contracts/shrincs/ShrincsWalletStorage.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

/// @dev Test harness exposing `ShrincsWallet` internals and a direct storage installer so
///      behavior tests can set up arbitrary state without threading a factory deploy.
contract ShrincsWalletHarness is ShrincsWallet {
    constructor(
        address payable factory_,
        address shrincsVerifier_
    ) ShrincsWallet(factory_, shrincsVerifier_) {}

    /// @dev Wraps the internal ERC-4337 `_validateSignature` for direct unit testing.
    function exposed_validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        return _validateSignature(userOp, userOpHash);
    }

    /// @dev Wraps the internal ERC-1271 check, returning the discriminated failure branch.
    function exposed_checkErc1271Signature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (Erc1271ValidationResult) {
        return _checkErc1271Signature(hash, signature);
    }

    /// @dev Wraps the canonical SHRINCS signing-domain separator.
    function exposed_shrincsDomainSeparator() external view returns (bytes32) {
        return _shrincsDomainSeparator();
    }

    /// @dev Wraps the eight-slot guard snapshot.
    function exposed_snapshotGuardedSlots()
        external
        view
        returns (bytes32[8] memory)
    {
        return _snapshotGuardedSlots();
    }

    /// @dev Test-only direct install of the wallet's PQ state, bypassing the factory
    ///      `initialize` path. NOT a production function.
    function harness_install(
        address owner_,
        bytes32 commitment,
        bytes32 erc1271Commitment,
        uint32 maxSignaturesValue
    ) external {
        _initializeOwner(owner_);
        Storage.Layout storage $ = Storage.layout();
        $.walletFactory = FACTORY;
        $.shrincsPublicKeyCommitment = commitment;
        $.erc1271StatelessCommitment = erc1271Commitment;
        $.maxSignatures = maxSignaturesValue;
    }

    /// @dev Records the installed bundle's trees as spent, mirroring what `initialize` does for a
    ///      factory-deployed wallet.
    function harness_spendTrees(SHRINCS.PublicKey calldata pk) external {
        _spendStatefulTree(_statefulTreeId(pk.statefulPublicKey));
        _spendStatelessTree(_statelessTreeId(pk.pkSeed, pk.hypertreeRoot));
    }

    /// @dev Wraps the tree-identity primitives.
    function exposed_statefulTreeId(bytes calldata statefulPublicKey) external pure returns (bytes32) {
        return _statefulTreeId(statefulPublicKey);
    }

    function exposed_statelessTreeId(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot
    ) external pure returns (bytes32) {
        return _statelessTreeId(pkSeed, hypertreeRoot);
    }

    /// @dev Wraps the check-and-record spend primitives.
    function exposed_spendStatefulTree(bytes32 treeId) external {
        _spendStatefulTree(treeId);
    }

    function exposed_spendStatelessTree(bytes32 treeId) external {
        _spendStatelessTree(treeId);
    }

    /// @dev Reads the spent-tree registries so tests can pin which install paths record trees.
    function harness_isStatefulTreeSpent(bytes32 treeId) external view returns (bool) {
        return Storage.layout().spentStatefulTrees[treeId];
    }

    function harness_isStatelessTreeSpent(bytes32 treeId) external view returns (bool) {
        return Storage.layout().spentStatelessTrees[treeId];
    }

    /// @dev Test-only setter to mark a stateful leaf consumed in the current key epoch (e.g. to
    ///      exercise the already-consumed branch). Routes through the real `_markStatefulLeafUsed`
    ///      and bumps the per-epoch used counter exactly as the production callers do.
    function harness_markLeafUsed(uint32 leaf) external {
        Storage.Layout storage $ = Storage.layout();
        _markStatefulLeafUsed($, $.keyVersion, leaf);
        $.statefulLeavesUsed += 1;
    }

    /// @dev Wraps the internal `_markStatefulLeafUsed` for direct unit testing against an explicit
    ///      key epoch (no counter bump — that is the caller's responsibility in production).
    function exposed_markStatefulLeafUsed(
        uint256 keyVersion_,
        uint256 leafIndex
    ) external {
        _markStatefulLeafUsed(Storage.layout(), keyVersion_, leafIndex);
    }

    /// @dev Wraps the internal `_isStatefulLeafUsed` read for a specific key epoch.
    function exposed_isStatefulLeafUsed(
        uint256 keyVersion_,
        uint256 leafIndex
    ) external view returns (bool) {
        return _isStatefulLeafUsed(Storage.layout(), keyVersion_, leafIndex);
    }

    /// @dev Wraps the consume-only stateful verify (no action-nonce advance — the
    ///      `markLeavesUsed` carve-out) so the nonce-neutrality can be pinned directly.
    function exposed_verifyStatefulAndConsume(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        bytes32 actionType,
        bytes32 payloadHash
    ) external returns (uint32) {
        return
            _verifyStatefulAndConsume(
                publicKey,
                signature,
                actionType,
                payloadHash
            );
    }

    /// @dev Wraps the shared stateful verify + bitmap consume so the budget/used/InvalidSignature
    ///      branches can be exercised directly (the leaf consume mutates state, so non-view).
    function exposed_verifyStatefulAndAdvance(
        SHRINCS.PublicKey calldata publicKey,
        SHRINCS.Signature calldata signature,
        bytes32 actionType,
        bytes32 payloadHash
    ) external returns (uint32) {
        return
            _verifyStatefulAndAdvance(
                publicKey,
                signature,
                actionType,
                payloadHash
            );
    }

    /// @dev Wraps the stateful revert-policy boundary around the external verifier (raw
    ///      message hash + pre-encoded envelope, exactly as the internal call sites pass them).
    function exposed_tryVerifyStateful(
        bytes32 expectedCommitment,
        bytes32 messageHash,
        bytes calldata envelope
    ) external view returns (bool) {
        return _tryVerifyStateful(expectedCommitment, messageHash, envelope);
    }

    /// @dev Wraps the stateless revert-policy boundary around the external verifier.
    function exposed_tryVerifyStateless(
        bytes32 expectedCommitment,
        bytes32 messageHash,
        bytes calldata envelope
    ) external view returns (bool) {
        return _tryVerifyStateless(expectedCommitment, messageHash, envelope);
    }

    /// @dev Wraps the guarded-slot tamper check so each of the eight slots can be mutated and the
    ///      `GuardedSlotTampered(index)` revert asserted.
    function exposed_assertGuardedSlotsUnchanged(
        bytes32[8] memory snapshot
    ) external view {
        _assertGuardedSlotsUnchanged(snapshot);
    }

    /// @dev Wraps the per-op execute-fee collection.
    function exposed_collectExecuteFee(uint256 maxFee) external {
        _collectExecuteFee(maxFee);
    }

    /// @dev Test-only setters writing directly to namespaced storage for boundary/namespace tests.
    function harness_setKeyVersion(uint256 keyVersion_) external {
        Storage.layout().keyVersion = keyVersion_;
    }

    function harness_setNonce(uint256 nonce_) external {
        Storage.layout().nonce = nonce_;
    }

    function harness_setMaxSignatures(uint32 maxSignaturesValue) external {
        Storage.layout().maxSignatures = maxSignaturesValue;
    }

    /// @dev Test-only setter to force the `$.walletFactory` snapshot slot away from the immutable
    ///      `FACTORY`, so the no-drift invariant (migrate re-establishes it) can be exercised.
    function harness_setWalletFactory(address payable walletFactory_) external {
        Storage.layout().walletFactory = walletFactory_;
    }

    /// @dev Wraps the owner-initialization guard. The wallet does NOT override it directly — it
    ///      inherits `_guardInitializeOwner() => true` from Solady's `ERC4337` base, which blocks
    ///      double-initialization (`_initializeOwner` reverts `AlreadyInitialized`). This pins that
    ///      inherited behavior.
    function exposed_guardInitializeOwner() external pure returns (bool) {
        return _guardInitializeOwner();
    }

    /// @dev Drives `migrate` inside the transient upgrade-guard context (mirrors the production
    ///      `upgradeToAndCall` gating) so the success path and `NotUpgrading` guard are testable
    ///      without a full UUPS round-trip.
    function harness_migrateInUpgradeContext(bytes calldata payload) external {
        uint256 slot = uint256(keccak256("quip.shrincs.wallet.upgrade.guard")) -
            1;
        assembly {
            tstore(slot, 1)
        }
        this.migrate(payload);
        assembly {
            tstore(slot, 0)
        }
    }
}
