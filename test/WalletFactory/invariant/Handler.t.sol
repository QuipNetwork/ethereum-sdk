// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";

/// @title FactoryImplStub
/// @dev Minimal contract whose runtime bytecode varies with `id`. Pre-deployed
///      in pairs (original + twin) by `WalletFactoryInvariantBase`:
///        - Two stubs with the same `id` share a codehash but live at
///          different addresses — exercises `undeprecateImplementation`'s
///          address-rebind path while keeping the codehash invariant.
///        - Two stubs with different `id` produce different codehashes —
///          gives the fuzz campaign multiple distinct vetted entries to
///          deprecate / undeprecate / interleave with fee updates.
contract FactoryImplStub {
    uint256 public immutable id;

    constructor(uint256 id_) {
        id = id_;
    }
}

/// @title WalletFactory Invariant Fuzz Handler
/// @dev Owns the factory under test (`factory.owner() == address(this)`) so
///      `onlyOwner` calls require no pranking. Maintains a fixed pool of
///      pre-deployed (original, twin) impl stubs; "twins" share their
///      sibling's codehash so the rebind branch of `undeprecateImplementation`
///      is reachable.
///
///      No fuzz selector touches ownership, withdrawal, wallet deployment,
///      or `updateWalletOwner` — those are governance / wallet-flow paths
///      and fall outside the implementation-lifecycle scope of this campaign.
///
///      Each fuzz entry point wraps its factory call in try/catch. Reverts
///      are counted; the invariant runner's `fail_on_revert = false` makes
///      caught reverts part of normal traversal.
contract WalletFactoryInvariantHandler is Test {
    WalletFactory public factory;

    /// @dev Address of the implementation pre-vetted by `WalletFactoryTest.setUp`.
    ///      Tracked so `everVetted*` reflects the factory's full vetted set,
    ///      including the seed entry the handler did not vet itself.
    address internal initialImpl;

    /// @dev Pool of original impl stubs (length == twin pool length). Index
    ///      `i` here pairs with index `i` in `twins`: both addresses, same
    ///      codehash. `originals[i]` is the address the handler passes to
    ///      `vetImplementation`; `twins[i]` is the rebind candidate.
    address[] internal originals;
    address[] internal twins;

    /// @dev True once `originals[i]` (and therefore its shared codehash) has
    ///      been vetted at least once. Sized 1:1 with `originals`.
    bool[] internal slotVetted;

    /// @dev Every codehash the handler has ever observed entering the vetted
    ///      set, in insertion order. Includes the seed `initialImpl`'s
    ///      codehash. Invariants iterate this to scan the full lifecycle.
    bytes32[] internal everVettedCodehashes;
    mapping(bytes32 => bool) internal codehashSeen;
    mapping(bytes32 => bool) internal expectedDeprecated;
    mapping(bytes32 => address) internal expectedImplementation;

    // Per-op success counters (reverts excluded).
    uint256 public callsVet;
    uint256 public callsDeprecate;
    uint256 public callsUndeprecate;
    uint256 public callsSetCreationFee;
    uint256 public callsSetExecuteFee;
    uint256 public expectedCreationFee;
    uint256 public expectedExecuteFee;
    uint256 public revertCount;
    uint256 public unexpectedSuccesses;
    uint256 public unexpectedFailures;

    /// @dev Called once from the base setUp after ownership has been handed
    ///      off to this handler. Records the seed impl and the pre-deployed
    ///      stub pool. Idempotent guard — a re-init would clobber mirrors.
    function initialize(
        WalletFactory factory_,
        address initialImpl_,
        address[] calldata originals_,
        address[] calldata twins_
    ) external {
        require(address(factory) == address(0), "handler already initialized");
        require(originals_.length == twins_.length, "pool length mismatch");
        factory = factory_;
        initialImpl = initialImpl_;
        for (uint256 i = 0; i < originals_.length; i++) {
            originals.push(originals_[i]);
            twins.push(twins_[i]);
            slotVetted.push(false);
        }
        _markCodehash(initialImpl_.codehash);
        expectedImplementation[initialImpl_.codehash] = initialImpl_;
    }

    /*══════════════════════════ helpers ════════════════════════════════*/

    function _markCodehash(bytes32 ch) internal {
        if (!codehashSeen[ch]) {
            codehashSeen[ch] = true;
            everVettedCodehashes.push(ch);
        }
    }

    /*════════════════════════ fuzz entry points ═════════════════════════*/

    /// @dev Vet a slot from the pre-deployed `originals` pool. Idx is
    ///      bounded to the pool. The factory will reject re-vetting a
    ///      codehash already in the set (`AlreadyVetted`); that path is a
    ///      valid revert and counted as such.
    function fuzzVetImplementation(uint256 idx) external {
        idx = bound(idx, 0, originals.length - 1);
        address impl = originals[idx];
        bool alreadyVetted = slotVetted[idx];
        try factory.vetImplementation(impl) {
            if (alreadyVetted) unexpectedSuccesses++;
            callsVet++;
            slotVetted[idx] = true;
            _markCodehash(impl.codehash);
            expectedImplementation[impl.codehash] = impl;
            expectedDeprecated[impl.codehash] = false;
        } catch {
            revertCount++;
            if (!alreadyVetted) unexpectedFailures++;
        }
    }

    /// @dev Deprecate one of the codehashes currently in the vetted set.
    ///      Picks by index into the handler's mirror (which mirrors the
    ///      factory's insertion order). When `useTwin` is true, targets
    ///      the same-codehash twin rather than the currently-registered
    ///      address so the address-mismatch branch of
    ///      `deprecateImplementation` (latest pointer vs a redeploy of
    ///      identical bytecode) is reachable; falls back to the registered
    ///      address when no twin exists (e.g. the seed impl).
    ///      Double-deprecation is not a contract revert today — the
    ///      factory just sets the bool idempotently — so success here is
    ///      monotone with respect to "ever deprecated."
    function fuzzDeprecateImplementation(uint256 idx, bool useTwin) external {
        if (everVettedCodehashes.length == 0) {
            revertCount++;
            return;
        }
        idx = bound(idx, 0, everVettedCodehashes.length - 1);
        bytes32 codehash = everVettedCodehashes[idx];
        address impl;
        if (useTwin) {
            impl = _findTwinForCodehash(codehash);
            if (impl == address(0)) {
                impl = factory.vettedWalletImpls(codehash);
            }
        } else {
            impl = factory.vettedWalletImpls(codehash);
        }
        try factory.deprecateImplementation(impl) {
            callsDeprecate++;
            expectedDeprecated[codehash] = true;
        } catch {
            revertCount++;
            unexpectedFailures++;
        }
    }

    /// @dev Undeprecate a codehash, optionally rebinding the registered
    ///      address to its twin so the `vettedWalletImpls[codehash] =
    ///      impl` swap in the contract is exercised. If `useTwin` is true
    ///      but no twin exists for the chosen codehash (e.g. the seed
    ///      impl), falls back to the currently-registered address.
    function fuzzUndeprecateImplementation(uint256 idx, bool useTwin) external {
        if (everVettedCodehashes.length == 0) {
            revertCount++;
            return;
        }
        idx = bound(idx, 0, everVettedCodehashes.length - 1);
        bytes32 codehash = everVettedCodehashes[idx];
        bool wasDeprecated = expectedDeprecated[codehash];
        address impl;
        if (useTwin) {
            impl = _findTwinForCodehash(codehash);
            if (impl == address(0)) {
                impl = factory.vettedWalletImpls(codehash);
            }
        } else {
            impl = factory.vettedWalletImpls(codehash);
        }
        try factory.undeprecateImplementation(impl) {
            if (!wasDeprecated) unexpectedSuccesses++;
            callsUndeprecate++;
            expectedDeprecated[codehash] = false;
            expectedImplementation[codehash] = impl;
        } catch {
            revertCount++;
            if (wasDeprecated) unexpectedFailures++;
        }
    }

    /// @dev Bounds the fee to `[0, MAX_FEE]` so the bound-check branch
    ///      doesn't dominate the fuzz revert distribution. Out-of-range
    ///      fees are covered by per-function behavior tests.
    function fuzzSetCreationFee(uint256 fee) external {
        fee = bound(fee, 0, factory.MAX_FEE());
        try factory.setCreationFee(fee) {
            callsSetCreationFee++;
            expectedCreationFee = fee;
        } catch {
            revertCount++;
            unexpectedFailures++;
        }
    }

    /// @dev See `fuzzSetCreationFee`.
    function fuzzSetExecuteFee(uint256 fee) external {
        fee = bound(fee, 0, factory.MAX_FEE());
        try factory.setExecuteFee(fee) {
            callsSetExecuteFee++;
            expectedExecuteFee = fee;
        } catch {
            revertCount++;
            unexpectedFailures++;
        }
    }

    /*════════════════════════ mirror getters ════════════════════════════*/

    function everVettedCount() external view returns (uint256) {
        return everVettedCodehashes.length;
    }

    function everVettedAt(uint256 i) external view returns (bytes32) {
        return everVettedCodehashes[i];
    }

    function deprecatedInMirror(bytes32 codehash) external view returns (bool) {
        return expectedDeprecated[codehash];
    }

    function implementationInMirror(
        bytes32 codehash
    ) external view returns (address) {
        return expectedImplementation[codehash];
    }

    function twinAt(uint256 index) external view returns (address) {
        return twins[index];
    }

    /*══════════════════════════ internals ══════════════════════════════*/

    /// @dev Linear scan over the pool for a twin whose codehash matches.
    ///      Pool size is small (single-digit), so linear is fine. Returns
    ///      the twin's address only if its sibling was actually vetted —
    ///      passing an unvetted twin to `undeprecateImplementation` is
    ///      always a revert path and provides no additional coverage.
    function _findTwinForCodehash(
        bytes32 codehash
    ) internal view returns (address) {
        for (uint256 i = 0; i < originals.length; i++) {
            if (slotVetted[i] && originals[i].codehash == codehash) {
                return twins[i];
            }
        }
        return address(0);
    }
}
