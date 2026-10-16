// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWallet} from "../../contracts/shrincs/ShrincsWallet.sol";
import {ShrincsWalletStorage as Storage} from "../../contracts/shrincs/ShrincsWalletStorage.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";

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

    /// @dev Wraps the internal `transferOwnership` acceptance check (the incoming party's
    ///      hybrid proof of control); returns the acceptance leaf on success.
    function exposed_verifyOwnershipAcceptance(
        SHRINCS.RotationTarget calldata nextKey,
        bytes32 nextCommitment,
        address newOwner,
        uint32 nextMaxSignatures,
        SHRINCS.Signature calldata keyAcceptance,
        bytes calldata ownerAcceptance
    ) external view returns (uint32) {
        return
            _verifyOwnershipAcceptance(
                nextKey,
                nextCommitment,
                newOwner,
                nextMaxSignatures,
                keyAcceptance,
                ownerAcceptance
            );
    }

    /// @dev Wraps the canonical SHRINCS signing-domain separator.
    function exposed_shrincsDomainSeparator() external view returns (bytes32) {
        return _shrincsDomainSeparator();
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
        $.erc1271PublicKeyCommitment = erc1271Commitment;
        $.maxSignatures = maxSignaturesValue;
    }

    /// @dev Storage-layout drift probe: writes a distinct sentinel into EVERY `Layout` field
    ///      through `Storage.layout()`, so a test can pin each field to its expected slot with
    ///      `vm.load`. Mapping entries are written under the given keys. NOT a production function.
    function harness_writeLayoutProbe(
        uint256 bitmapKeyVersion,
        uint256 bitmapWord,
        bytes32 statefulTreeId,
        bytes32 statelessTreeId
    ) external {
        Storage.Layout storage $ = Storage.layout();
        $.walletFactory = payable(address(uint160(0xA1)));
        $.shrincsPublicKeyCommitment = bytes32(uint256(0xA2));
        $.erc1271PublicKeyCommitment = bytes32(uint256(0xA3));
        $.keyVersion = 0xA4;
        $.nonce = 0xA5;
        $.statefulLeavesUsed = 0xA6;
        $.maxSignatures = 0xA7;
        $.usedStatefulLeafBitmap[bitmapKeyVersion][bitmapWord] = 0xA8;
        $.spentStatefulTrees[statefulTreeId] = true;
        $.spentStatelessTrees[statelessTreeId] = true;
    }

    /// @dev The slot `Storage.layout()` resolves to.
    function exposed_layoutSlot() external pure returns (bytes32 slot) {
        Storage.Layout storage $ = Storage.layout();
        assembly {
            slot := $.slot
        }
    }

    /// @dev Records the installed bundle's trees as spent, mirroring what `initialize` does for a
    ///      factory-deployed wallet.
    function harness_spendTrees(SHRINCS.PublicKey calldata pk) external {
        _safeInstallStatefulKey(pk.statefulPublicKey);
        _safeInstallStatelessKey(pk.pkSeed, pk.hypertreeRoot);
    }

    /// @dev Wraps the tree-identity primitives (decoding the 68-byte stateful encoding first,
    ///      mirroring `_safeInstallStatefulKey`).
    function exposed_statefulTreeId(bytes calldata statefulPublicKey) external pure returns (bytes32) {
        (UXMSS.StatefulPublicKey memory decoded, bool ok) = SHRINCS
            .decodeStatefulPublicKey(statefulPublicKey);
        if (!ok) revert CommitmentMismatch();
        return _statefulTreeId(decoded);
    }

    function exposed_statelessTreeId(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot
    ) external pure returns (bytes32) {
        return _statelessTreeId(pkSeed, hypertreeRoot);
    }

    /// @dev Wraps the whole-bundle install (validate + derive commitment + install both halves).
    function exposed_safeInstallKeyBundle(SHRINCS.PublicKey calldata pk) external returns (bytes32) {
        return _safeInstallKeyBundle(pk);
    }

    /// @dev Wraps the install-payload decoder/validator.
    function exposed_decodeAndValidateInstall(bytes calldata payload)
        external
        pure
        returns (
            bytes32 declaredCommitment,
            uint32 maxSignatures,
            SHRINCS.PublicKey memory mainKey,
            SHRINCS.PublicKey memory erc1271Key
        )
    {
        return _decodeAndValidateInstall(payload);
    }

    /// @dev Wraps the check-and-record install primitives.
    function exposed_safeInstallStatefulKey(bytes calldata statefulPublicKey) external {
        _safeInstallStatefulKey(statefulPublicKey);
    }

    function exposed_safeInstallStatelessKey(
        bytes calldata pkSeed,
        bytes calldata hypertreeRoot
    ) external {
        _safeInstallStatelessKey(pkSeed, hypertreeRoot);
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

    /// @dev Exposes the `migrate` entry gate for direct unit testing.
    function exposed_enforceUpgradeInFlight() external view {
        _enforceUpgradeInFlight();
    }

    /// @dev Wraps the UUPS authorization hook (`onlyOwner`) — the defense-in-depth gate
    ///      `super.upgradeToAndCall` runs behind the wallet's own `onlyOwner`.
    function exposed_authorizeUpgrade(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }

    /// @dev Wraps the wallet's own ERC-1967 pointer read.
    function exposed_msgImplementation() external view returns (address) {
        return _msgImplementation();
    }

    /// @dev Wraps the single leaf-index derivation point (authPath length).
    function exposed_leafIndex(SHRINCS.Signature calldata signature) external pure returns (uint32) {
        return _leafIndex(signature);
    }

    /// @dev Wraps the stateless full-rotation validator (shape checks + commitment recompute +
    ///      recovery-signature verify; zero return = reject).
    function exposed_statelessRotate(
        bytes32 expectedCommitment,
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.RotationContext memory ctx,
        SPHINCSPlusC.Signature calldata recoverySignature,
        SHRINCS.RotationTarget calldata nextKey
    ) external view returns (bytes32) {
        return _statelessRotate(expectedCommitment, currentPublicKey, ctx, recoverySignature, nextKey);
    }
}
