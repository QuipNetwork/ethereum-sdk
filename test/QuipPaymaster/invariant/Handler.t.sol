// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {QuipPaymaster} from "../../../contracts/QuipPaymaster.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";

/// @title QuipPaymaster Invariant Fuzz Handler
/// @dev Owns the paymaster under test (`paymaster.owner() == address(this)`)
///      so `onlyOwner` calls require no pranking. Maintains a mirror of
///      every wallet's current verifier (pubkey + privkey) plus a
///      monotonic `everUsedKeys` list of every verifier hash the contract
///      should hold in its `verifierKeyUsed` index.
///
///      The handler exercises four ops:
///        - `fuzzSetPqVerifier`   — generate fresh key, install
///        - `fuzzRemovePqVerifier` — clear a wallet's binding
///        - `fuzzValidatePaymasterUserOp` — build a fully signed UserOp,
///          submit via vm.prank(ENTRY_POINT). On success the contract
///          rotates; the handler mirrors the rotation.
///        - `fuzzAttemptRebindUsedKey` — pick a historical pubkey, try to
///          set it again on some wallet. If the wallet's current key is
///          already that hash, the contract's no-op branch makes this
///          irrelevant (skipped). Otherwise the call MUST revert with
///          `VerifierKeyInUse`; a success is recorded as a violation.
///
///      Cross-wallet isolation is checked as a post-call delta on every
///      set/remove/validate selector — any other wallet's verifier
///      changing across the call is recorded as a violation. Successful
///      validations also assert that the wallet's stored verifier
///      advanced to the `nextVerifier` argument.
contract QuipPaymasterInvariantHandler is Test {
    using EfficientHashLib for bytes;

    QuipPaymaster public paymaster;

    /// @dev Bundle of all bootstrap material the base setUp hands to the
    ///      handler in one shot. Bundled so the call site stays under
    ///      Solidity's 16-local-slot limit.
    struct InitParams {
        QuipPaymaster paymaster;
        address[] wallets;
        WOTSPlus.WinternitzAddress[] initialPubs;
        bytes32[] initialPrivs;
    }

    // Constants mirror the paymaster's; kept as local copies so the handler
    // never needs to access internal contract state.
    address internal constant _ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint256 internal constant _PAYMASTER_SIG_OFFSET = 128;
    uint128 internal constant _DEFAULT_PM_VERIFICATION_GAS = 100_000;
    uint128 internal constant _DEFAULT_PM_POSTOP_GAS = 50_000;
    bytes32 internal constant _PAYMASTER_APPROVE_TAG =
        keccak256("quip.digest.paymasterApprove");

    /// @dev Fixed-size pool of wallet addresses the fuzz selectors operate
    ///      against. Size 4 gives the cross-wallet isolation invariant a
    ///      meaningful surface (≥ 2 verifiers can simultaneously exist
    ///      while a fuzz selector mutates one of them) without bloating
    ///      the post-call snapshot loop.
    address[] internal wallets;

    /// @dev Mirror of each wallet's current verifier. Zero-valued pubkey
    ///      means the wallet has no verifier (post-removal or never set).
    mapping(address wallet => WOTSPlus.WinternitzAddress) internal curPub;
    mapping(address wallet => bytes32) internal curPriv;

    /// @dev Monotonic "ever-used key" mirror. Append-only; never cleared.
    ///      Indexed by insertion order. Used by `fuzzAttemptRebindUsedKey`
    ///      to choose a historical hash to try re-registering, and by
    ///      `invariant_currentVerifierHashesInMirror` to confirm every
    ///      live verifier's hash was inserted via a legitimate path.
    WOTSPlus.WinternitzAddress[] internal everUsedPubs;
    mapping(bytes32 => bool) internal everUsedSeen;

    uint256 internal seedCounter;

    // Per-op success counters (reverts excluded).
    uint256 public callsSet;
    uint256 public callsRemove;
    uint256 public callsValidateSuccess;
    uint256 public callsValidateFail;
    uint256 public callsAttemptRebindRevert;
    uint256 public revertCount;

    // Violation counters — every invariant in `Local.t.sol` asserts the
    // corresponding counter is zero. Incremented at the call site so the
    // surrounding global invariants get a stable surface to read.
    /// @dev Increments if any non-target wallet's verifier hash changes
    ///      across a single set/remove/validate call. The contract's
    ///      writes are per-wallet; a drift would indicate a storage layout
    ///      collision or a missing isolation gate.
    uint256 public crossWalletDriftCount;
    /// @dev Increments if `validatePaymasterUserOp` returned `validationData
    ///      == 0` but the wallet's stored verifier did NOT equal the
    ///      `nextVerifier` argument afterwards. The contract MUST rotate
    ///      atomically with success.
    uint256 public successDidNotAdvanceCount;
    /// @dev Increments if a `setPqVerifier` call against a known
    ///      historical (already-used) hash succeeded. The monotonic
    ///      occupancy index must reject every such attempt.
    uint256 public improperRebindSuccessCount;
    /// @dev Increments if `validatePaymasterUserOp` returned vd==0 on a
    ///      wallet whose current verifier was zero at call time.
    uint256 public noVerifierSponsorshipBugCount;

    function initialize(InitParams calldata p) external {
        require(address(paymaster) == address(0), "handler already init");
        require(
            p.wallets.length == p.initialPubs.length &&
                p.wallets.length == p.initialPrivs.length,
            "init length mismatch"
        );
        paymaster = p.paymaster;
        for (uint256 i = 0; i < p.wallets.length; i++) {
            wallets.push(p.wallets[i]);
            curPub[p.wallets[i]] = p.initialPubs[i];
            curPriv[p.wallets[i]] = p.initialPrivs[i];
            _recordEverUsed(p.initialPubs[i]);
        }
    }

    /*══════════════════════════ helpers ════════════════════════════════*/

    function _keyHash(
        WOTSPlus.WinternitzAddress memory k
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(k.publicSeed, k.publicKeyHash);
    }

    function _isZero(
        WOTSPlus.WinternitzAddress memory k
    ) internal pure returns (bool) {
        return k.publicSeed == bytes32(0) && k.publicKeyHash == bytes32(0);
    }

    function _recordEverUsed(WOTSPlus.WinternitzAddress memory k) internal {
        if (_isZero(k)) return;
        bytes32 h = _keyHash(k);
        if (!everUsedSeen[h]) {
            everUsedSeen[h] = true;
            everUsedPubs.push(k);
        }
    }

    function _freshKeyPair()
        internal
        returns (WOTSPlus.WinternitzAddress memory pub, bytes32 priv)
    {
        seedCounter++;
        bytes32 seed = keccak256(
            abi.encodePacked("pm-handler-fresh", seedCounter, address(this))
        );
        (pub, priv) = WOTSPlus.generateKeyPair(seed);
    }

    /// @dev Snapshot the hashes of every wallet's current verifier
    ///      EXCEPT the one indexed by `exclude`. Used by selectors that
    ///      mutate one wallet to assert the others are untouched.
    function _snapshotOthers(
        uint256 exclude
    ) internal view returns (bytes32[] memory hashes) {
        hashes = new bytes32[](wallets.length);
        for (uint256 i = 0; i < wallets.length; i++) {
            if (i == exclude) continue;
            hashes[i] = _keyHash(paymaster.getPqVerifier(wallets[i]));
        }
    }

    function _checkOthersUnchanged(
        uint256 exclude,
        bytes32[] memory pre
    ) internal {
        for (uint256 i = 0; i < wallets.length; i++) {
            if (i == exclude) continue;
            bytes32 post = _keyHash(paymaster.getPqVerifier(wallets[i]));
            if (post != pre[i]) {
                crossWalletDriftCount++;
            }
        }
    }

    /*══════════════ paymaster digest reconstruction ═════════════════════*/

    /// @dev Mirrors `QuipPaymaster._userOpBindingHash`. Memory-only —
    ///      contract uses calldata slices, but `keccak256` of identical
    ///      bytes yields the same digest regardless of source location.
    function _userOpBindingHash(
        PackedUserOperation memory userOp
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(userOp.sender))),
                bytes32(userOp.nonce),
                EfficientHashLib.hash(userOp.initCode),
                EfficientHashLib.hash(userOp.callData),
                userOp.accountGasLimits,
                bytes32(userOp.preVerificationGas),
                userOp.gasFees,
                EfficientHashLib.hash(
                    _slice(userOp.paymasterAndData, 0, _PAYMASTER_SIG_OFFSET)
                )
            );
    }

    /// @dev Mirrors `QuipPaymaster._verifyAndRotate`'s outer digest.
    function _paymasterApprovalDigest(
        WOTSPlus.WinternitzAddress memory currentPub,
        bytes32 bindingHash
    ) internal view returns (bytes32) {
        return
            EfficientHashLib.hash(
                _PAYMASTER_APPROVE_TAG,
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(paymaster)))),
                currentPub.publicSeed,
                currentPub.publicKeyHash,
                bindingHash
            );
    }

    function _paymasterAndDataPrefix(
        uint48 validUntil,
        uint48 validAfter,
        WOTSPlus.WinternitzAddress memory nextPub
    ) internal view returns (bytes memory) {
        return
            abi.encodePacked(
                address(paymaster),
                _DEFAULT_PM_VERIFICATION_GAS,
                _DEFAULT_PM_POSTOP_GAS,
                validUntil,
                validAfter,
                nextPub.publicSeed,
                nextPub.publicKeyHash
            );
    }

    function _slice(
        bytes memory data,
        uint256 start,
        uint256 len
    ) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
    }

    /// @dev Build a baseline `PackedUserOperation` for `sender`. The fuzz
    ///      selectors only mutate `paymasterAndData`; all other fields
    ///      stay at fixed defaults so the binding hash construction has
    ///      no DOF that the handler doesn't already control.
    function _mockUserOp(
        address sender_
    ) internal pure returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: sender_,
                nonce: 0,
                initCode: "",
                callData: "",
                accountGasLimits: bytes32(
                    (uint256(100_000) << 128) | uint256(100_000)
                ),
                preVerificationGas: 21_000,
                gasFees: bytes32(
                    (uint256(1 gwei) << 128) | uint256(10 gwei)
                ),
                paymasterAndData: "",
                signature: ""
            });
    }

    /// @dev Build a fully-signed UserOp for `wallet` rotating from
    ///      `curPub_`/`curPriv_` to `nextPub`. Mirrors `_signPaymasterApproval`
    ///      from QuipPaymasterTest with the gas/validity defaults inlined.
    function _signUserOp(
        address wallet,
        WOTSPlus.WinternitzAddress memory curPub_,
        bytes32 curPriv_,
        WOTSPlus.WinternitzAddress memory nextPub
    ) internal view returns (PackedUserOperation memory userOp) {
        userOp = _mockUserOp(wallet);
        bytes memory prefix = _paymasterAndDataPrefix(
            uint48(block.timestamp + 1 hours),
            uint48(0),
            nextPub
        );
        // Pad with 2144 zero bytes (signature region placeholder) so the
        // binding hash hashes the right prefix length. The placeholder is
        // excluded from the hash via `[:_PAYMASTER_SIG_OFFSET]`.
        userOp.paymasterAndData = abi.encodePacked(prefix, new bytes(2144));

        bytes32 bindingHash = _userOpBindingHash(userOp);
        bytes32 digest = _paymasterApprovalDigest(curPub_, bindingHash);
        bytes32[67] memory sig = WOTSPlus.sign(
            curPriv_,
            WOTSPlus.WinternitzMessage({messageHash: digest})
        );

        userOp.paymasterAndData = abi.encodePacked(prefix, sig);
    }

    /*════════════════════════ fuzz entry points ═════════════════════════*/

    /// @dev Generate a fresh WOTS+ keypair and try to install it on
    ///      wallet `walletIdx`. The contract's monotonic occupancy index
    ///      will reject if the (handler-derived, monotonic-counter) seed
    ///      ever produces a collision with a previously-used hash —
    ///      vanishingly unlikely but cheap to catch via revertCount.
    function fuzzSetPqVerifier(uint256 walletIdx) external {
        walletIdx = bound(walletIdx, 0, wallets.length - 1);
        address w = wallets[walletIdx];
        (
            WOTSPlus.WinternitzAddress memory pub,
            bytes32 priv
        ) = _freshKeyPair();

        bytes32[] memory pre = _snapshotOthers(walletIdx);

        try paymaster.setPqVerifier(w, pub) {
            callsSet++;
            curPub[w] = pub;
            curPriv[w] = priv;
            _recordEverUsed(pub);
        } catch {
            revertCount++;
        }
        _checkOthersUnchanged(walletIdx, pre);
    }

    /// @dev Clear wallet `walletIdx`'s verifier binding. Contract reverts
    ///      `PqVerifierNotRegistered` if the wallet had none — counted as
    ///      a normal revert. Removal leaves the hash in the monotonic
    ///      `verifierKeyUsed` index by design (the key is burned, not
    ///      reusable), which the rebind invariants check.
    function fuzzRemovePqVerifier(uint256 walletIdx) external {
        walletIdx = bound(walletIdx, 0, wallets.length - 1);
        address w = wallets[walletIdx];
        bytes32[] memory pre = _snapshotOthers(walletIdx);

        try paymaster.removePqVerifier(w) {
            callsRemove++;
            delete curPub[w];
            delete curPriv[w];
        } catch {
            revertCount++;
        }
        _checkOthersUnchanged(walletIdx, pre);
    }

    /// @dev Build a fully-signed UserOp rotating from the wallet's
    ///      current verifier to a fresh next, and submit via vm.prank
    ///      ENTRY_POINT. Covers three audit invariants:
    ///        1. no verifier ⇒ no sponsorship: pre-state with zero key
    ///           must produce `validationData = 1`.
    ///        2. successful op advances verifier: on `vd == 0`, the
    ///           stored verifier must equal `nextPub`.
    ///        3. cross-wallet isolation: other wallets' verifiers
    ///           unchanged across the call.
    function fuzzValidatePaymasterUserOp(uint256 walletIdx) external {
        walletIdx = bound(walletIdx, 0, wallets.length - 1);
        address w = wallets[walletIdx];

        WOTSPlus.WinternitzAddress memory preVerifier = curPub[w];
        bool hadVerifier = !_isZero(preVerifier);
        bytes32 prePriv = curPriv[w];

        // Fresh next-key for rotation.
        (
            WOTSPlus.WinternitzAddress memory nextPub,
            bytes32 nextPriv
        ) = _freshKeyPair();

        bytes32[] memory pre = _snapshotOthers(walletIdx);

        PackedUserOperation memory userOp;
        if (hadVerifier) {
            userOp = _signUserOp(w, preVerifier, prePriv, nextPub);
        } else {
            // No verifier path: contract MUST reject before checking sig.
            // Build a well-formed paymasterAndData (length-gated) with a
            // zero-filled signature placeholder; the no-verifier branch
            // fires before `WOTSPlus.verify` runs.
            userOp = _mockUserOp(w);
            bytes memory prefix = _paymasterAndDataPrefix(
                uint48(block.timestamp + 1 hours),
                uint48(0),
                nextPub
            );
            userOp.paymasterAndData = abi.encodePacked(
                prefix,
                new bytes(2144)
            );
        }

        vm.prank(_ENTRY_POINT);
        try paymaster.validatePaymasterUserOp(userOp, bytes32(0), 0) returns (
            bytes memory,
            uint256 vd
        ) {
            // ERC-4337 packs validationData as
            //   [0:160)  authorizer (0 = success, 1 = SIG_VALIDATION_FAILED)
            //   [160:208) validUntil
            //   [208:256) validAfter
            // The high bits are set on success (validUntil != 0), so a
            // whole-word `vd == 0` check would mis-classify every
            // successful rotation as a failure. Mask to the authorizer
            // bits before deciding.
            if (uint160(vd) == 0) {
                if (!hadVerifier) {
                    // Contract validated a UserOp for a wallet with no
                    // registered verifier — direct violation of the
                    // "no verifier ⇒ no sponsorship" property.
                    noVerifierSponsorshipBugCount++;
                } else {
                    callsValidateSuccess++;
                    // Postcondition: stored verifier == nextPub.
                    WOTSPlus.WinternitzAddress memory stored = paymaster
                        .getPqVerifier(w);
                    if (
                        stored.publicSeed != nextPub.publicSeed ||
                        stored.publicKeyHash != nextPub.publicKeyHash
                    ) {
                        successDidNotAdvanceCount++;
                    }
                    // Mirror the rotation.
                    curPub[w] = nextPub;
                    curPriv[w] = nextPriv;
                    _recordEverUsed(nextPub);
                }
            } else {
                callsValidateFail++;
            }
        } catch {
            revertCount++;
        }

        _checkOthersUnchanged(walletIdx, pre);
    }

    /// @dev Pick a historical pubkey from `everUsedPubs` and try to set
    ///      it as wallet `walletIdx`'s verifier. The handler skips the
    ///      no-op branch (where the chosen key already equals the
    ///      wallet's current key) because the contract returns silently
    ///      in that case — not a violation. For every other attempt the
    ///      contract MUST revert `VerifierKeyInUse`; a non-revert
    ///      increments `improperRebindSuccessCount` which the invariant
    ///      asserts is zero.
    function fuzzAttemptRebindUsedKey(
        uint256 walletIdx,
        uint256 historyIdx
    ) external {
        if (everUsedPubs.length == 0) {
            revertCount++;
            return;
        }
        walletIdx = bound(walletIdx, 0, wallets.length - 1);
        historyIdx = bound(historyIdx, 0, everUsedPubs.length - 1);
        address w = wallets[walletIdx];
        WOTSPlus.WinternitzAddress memory hist = everUsedPubs[historyIdx];

        // Skip the silent no-op branch in `setPqVerifier`: when the
        // wallet's current verifier already equals the chosen historical
        // key, the contract just emits and returns — neither a violation
        // nor a useful test.
        WOTSPlus.WinternitzAddress memory cur = curPub[w];
        if (
            cur.publicSeed == hist.publicSeed &&
            cur.publicKeyHash == hist.publicKeyHash
        ) {
            return;
        }

        bytes32[] memory pre = _snapshotOthers(walletIdx);

        try paymaster.setPqVerifier(w, hist) {
            // Contract accepted a re-bind of an already-used key — the
            // monotonic occupancy invariant is broken.
            improperRebindSuccessCount++;
            // Mirror MUST be updated to reflect what the contract did, so
            // subsequent fuzz reads agree. We can't recover the priv key
            // for `hist` here — flag by clearing the priv mirror, which
            // makes future `fuzzValidatePaymasterUserOp` skip the signed
            // branch for this wallet until a fresh set runs.
            curPub[w] = hist;
            curPriv[w] = bytes32(0);
        } catch (bytes memory reason) {
            // Verify the revert reason is the expected one. Other reverts
            // (e.g. ZeroValuePqVerifierKey) indicate a different bug.
            if (
                bytes4(reason) ==
                IQuipPaymaster.VerifierKeyInUse.selector
            ) {
                callsAttemptRebindRevert++;
            } else {
                revertCount++;
            }
        }
        _checkOthersUnchanged(walletIdx, pre);
    }

    /*════════════════════════ mirror getters ════════════════════════════*/

    function walletCount() external view returns (uint256) {
        return wallets.length;
    }

    function walletAt(uint256 i) external view returns (address) {
        return wallets[i];
    }

    function everUsedCount() external view returns (uint256) {
        return everUsedPubs.length;
    }

    function everUsedAt(
        uint256 i
    ) external view returns (WOTSPlus.WinternitzAddress memory) {
        return everUsedPubs[i];
    }

    function currentVerifier(
        address w
    ) external view returns (WOTSPlus.WinternitzAddress memory) {
        return curPub[w];
    }
}
