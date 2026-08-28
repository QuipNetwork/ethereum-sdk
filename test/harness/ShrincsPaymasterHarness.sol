// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsPaymaster} from "../../contracts/ShrincsPaymaster.sol";
import {ShrincsPaymasterStorage as Storage} from "../../contracts/storage/ShrincsPaymasterStorage.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";

/// @dev Test harness exposing `ShrincsPaymaster` internals and a direct storage installer so
///      behavior tests can set up arbitrary verifier state without an owner-gated registration.
contract ShrincsPaymasterHarness is ShrincsPaymaster {
    constructor(
        address shrincsVerifier_
    ) ShrincsPaymaster(shrincsVerifier_) {}

    /// @dev Wraps the internal SHRINCS verify + bitmap leaf consume for direct unit testing.
    function exposed_verifyAndAdvance(
        PackedUserOperation calldata userOp
    ) external returns (bool) {
        return _verifyAndAdvance(userOp);
    }

    /// @dev Wraps the userOp binding hash that the off-chain sponsor must replicate.
    function exposed_userOpBindingHash(
        PackedUserOperation calldata userOp
    ) external pure returns (bytes32) {
        return _userOpBindingHash(userOp);
    }

    /// @dev Wraps the paymaster's canonical signing-domain separator.
    function exposed_domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @dev Test-only direct install of the global verifier state, bypassing the owner-gated
    ///      `initialize`/`rotateStatefulKey` paths (no epoch bump). NOT a production function.
    function harness_install(
        bytes32 commitment,
        uint32 maxSignaturesValue
    ) external {
        Storage.Layout storage $ = Storage.layout();
        $.shrincsCommitment = commitment;
        $.maxSignatures = maxSignaturesValue;
    }

    /// @dev Wraps `_statefulTreeId` over the 68-byte encoding (decode, then keccak256(pkSeed ‖ root)).
    function exposed_statefulTreeId(bytes calldata statefulPublicKey) external pure returns (bytes32) {
        (UXMSS.StatefulPublicKey memory decoded, bool ok) = SHRINCS.decodeStatefulPublicKey(statefulPublicKey);
        require(ok, "statefulPublicKey");
        return _statefulTreeId(decoded);
    }

    /// @dev Wraps the check-and-record spend primitive (also used by the fixture to mirror
    ///      what `initialize` records).
    function exposed_spendStatefulTree(bytes32 treeId) external {
        _spendStatefulTree(treeId);
    }

    /// @dev Reads the spent-tree registry so tests can pin which install paths record trees.
    function harness_isStatefulTreeSpent(bytes32 treeId) external view returns (bool) {
        return Storage.layout().spentStatefulTrees[treeId];
    }

    /// @dev Test-only setter to mark a stateful leaf consumed in the current epoch (e.g. to
    ///      exercise the already-consumed branch). Routes through the real `_markStatefulLeafUsed`
    ///      and bumps the per-epoch used counter exactly as the production callers do.
    function harness_markLeafUsed(uint32 leaf) external {
        Storage.Layout storage $ = Storage.layout();
        _markStatefulLeafUsed($, $.keyVersion, leaf);
        $.statefulLeavesUsed += 1;
    }

    /// @dev Wraps the internal `_markStatefulLeafUsed` for direct unit testing against an explicit
    ///      key epoch (no counter bump — that is the caller's responsibility in production).
    function exposed_markStatefulLeafUsed(uint256 keyVersion_, uint256 leafIndex) external {
        _markStatefulLeafUsed(Storage.layout(), keyVersion_, leafIndex);
    }

    /// @dev Wraps the internal `_isStatefulLeafUsed` read for a specific key epoch.
    function exposed_isStatefulLeafUsed(uint256 keyVersion_, uint256 leafIndex) external view returns (bool) {
        return _isStatefulLeafUsed(Storage.layout(), keyVersion_, leafIndex);
    }

    /// @dev Wraps the owner-initialization guard (overridden to `true` because the paymaster does
    ///      not inherit Solady's `ERC4337` base).
    function exposed_guardInitializeOwner() external pure returns (bool) {
        return _guardInitializeOwner();
    }

    /// @dev Test-only setter writing the verifier epoch directly for namespace tests.
    function harness_setKeyVersion(uint256 keyVersion_) external {
        Storage.layout().keyVersion = keyVersion_;
    }

    /// @dev Test-only owner installer for the etched harness (its constructor never runs, so the
    ///      owner is unset). The guarded `_initializeOwner` reverts on a second call.
    function harness_setOwner(address owner_) external {
        _initializeOwner(owner_);
    }

    /// @dev Wraps the upgrade authorization gate (`onlyOwner`).
    function exposed_authorizeUpgrade(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }

    /// @dev Test convenience: the per-epoch consumed-leaf counter (the production contract exposes
    ///      it via `getShrincsVerifier` / `remainingStatefulSignatures`).
    function statefulLeavesUsed() external view returns (uint32) {
        return Storage.layout().statefulLeavesUsed;
    }
}
