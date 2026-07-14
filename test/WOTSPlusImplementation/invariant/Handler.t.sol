// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementation} from "../../../contracts/wots/WOTSPlusImplementation.sol";

/// @title WOTSPlusImplementation Invariant Fuzz Handler
/// @dev Owns the wallet under test (`wallet.owner() == address(this)`) so
///      `onlyOwner` calls require no pranking.
///
///      Key tracking: a `keyHash => privKey` mapping for each signing-
///      capable keyset (transaction, recovery). When the handler needs to
///      pick a signing key, it queries `wallet.getKeyset(kind)` for the
///      currently-live pubkeys and looks up the matching priv by hash.
///      This avoids the bookkeeping fragility of mirroring the keyset's
///      internal index order across `replaceKeys` rotations, which the
///      underlying `EnumerableWinternitzAddressSet` reorders via swap-and-
///      pop. Verification keys aren't tracked (no fuzz op signs as
///      verification); their old-key picks come straight from
///      `wallet.getKeyset(Verification)`.
///
///      Fresh "next" keys derive from a monotonic `seedCounter`, so no two
///      ops ever request the same seed; combined with the wallet's
///      `isKeySpent` burn index, this prevents accidental key-reuse
///      reverts that would otherwise dominate the fuzz tree.
///
///      Each fuzz entry point wraps the wallet call in try/catch. On
///      success, the local mirror is updated; on revert, only the
///      `revertCount` stat moves. `forge invariant`'s default
///      `fail_on_revert = false` means caught reverts are fine — the
///      invariant runner just continues with the next call.
contract WOTSPlusImplementationInvariantHandler is Test {
    /// @dev Bundle of all bootstrap material. Bundled into a struct so
    ///      `initialize` doesn't blow past Solidity's 16-local-slot limit.
    struct InitParams {
        WOTSPlusImplementation wallet;
        WOTSPlus.WinternitzAddress[10] txnPubs;
        bytes32[10] txnPrivs;
        WOTSPlus.WinternitzAddress[10] recPubs;
        bytes32[10] recPrivs;
        WOTSPlus.WinternitzAddress[10] verPubs;
        WOTSPlus.WinternitzAddress disasterPub;
        bytes32 disasterPriv;
        WOTSPlus.WinternitzAddress ownershipPub;
        bytes32 ownershipPriv;
        address[] vettedImpls;
    }

    WOTSPlusImplementation public wallet;

    // keyHash → privKey for signing-capable keysets.
    mapping(bytes32 => bytes32) internal txnPriv;
    mapping(bytes32 => bytes32) internal recPriv;

    // Single-slot signing keys. Disaster signs `saveWallet`; ownership
    // signs `transferOwnership(bytes)`. Both rotate on use.
    WOTSPlus.WinternitzAddress internal disasterPub;
    bytes32 internal disasterPriv;
    WOTSPlus.WinternitzAddress internal ownershipPub;
    bytes32 internal ownershipPriv;

    /// @dev All implementations the factory has vetted at handler init.
    ///      `fuzzUpgradeToAndCall` / `fuzzRecoveryUpgrade` rotate the
    ///      proxy among these. The list is fixed across the campaign —
    ///      no fuzz op vets new impls.
    address[] internal vettedImpls;

    // Monotonic burn-set mirror: every key the handler has ever
    // installed (full pubkey, not just hash, so the invariant can probe
    // `wallet.isKeySpent(key)` directly). Read via `everInstalledAt`.
    WOTSPlus.WinternitzAddress[] internal everInstalled;

    uint256 internal seedCounter;

    bytes32 internal constant _ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // Per-op success counters (reverts excluded).
    uint256 public callsExecute;
    uint256 public callsWithdraw;
    uint256 public callsResetTxn;
    uint256 public callsResetRec;
    uint256 public callsResetVer;
    uint256 public callsReplaceTxnInTxn;
    uint256 public callsReplaceVerInTxn;
    uint256 public callsReplaceRecInTxn;
    uint256 public callsReplaceTxnInRec;
    uint256 public callsReplaceRecInRec;
    uint256 public callsReplaceVerInRec;
    uint256 public callsSaveWallet;
    uint256 public callsTransferOwnership;
    uint256 public callsUpgradeToAndCall;
    uint256 public callsRecoveryUpgrade;
    uint256 public revertCount;

    function initialize(InitParams calldata p) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = p.wallet;
        for (uint256 i = 0; i < 10; i++) {
            _installTxnKey(p.txnPubs[i], p.txnPrivs[i]);
            _installRecKey(p.recPubs[i], p.recPrivs[i]);
            _markEverInstalled(p.verPubs[i]);
        }
        disasterPub = p.disasterPub;
        disasterPriv = p.disasterPriv;
        _markEverInstalled(p.disasterPub);
        ownershipPub = p.ownershipPub;
        ownershipPriv = p.ownershipPriv;
        _markEverInstalled(p.ownershipPub);
        for (uint256 i = 0; i < p.vettedImpls.length; i++) {
            vettedImpls.push(p.vettedImpls[i]);
        }
    }

    receive() external payable {}

    /*══════════════════════════ helpers ════════════════════════════════*/

    function _keyHash(WOTSPlus.WinternitzAddress memory k) internal pure returns (bytes32) {
        return keccak256(abi.encode(k));
    }

    function _installTxnKey(WOTSPlus.WinternitzAddress memory pub, bytes32 priv) internal {
        txnPriv[_keyHash(pub)] = priv;
        everInstalled.push(pub);
    }

    function _installRecKey(WOTSPlus.WinternitzAddress memory pub, bytes32 priv) internal {
        recPriv[_keyHash(pub)] = priv;
        everInstalled.push(pub);
    }

    function _markEverInstalled(WOTSPlus.WinternitzAddress memory pub) internal {
        everInstalled.push(pub);
    }

    function _consumeTxnKey(WOTSPlus.WinternitzAddress memory pub) internal {
        delete txnPriv[_keyHash(pub)];
    }

    function _consumeRecKey(WOTSPlus.WinternitzAddress memory pub) internal {
        delete recPriv[_keyHash(pub)];
    }

    function _freshKeyPair() internal returns (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) {
        seedCounter++;
        bytes32 seed = keccak256(abi.encodePacked("handler-fresh", seedCounter, address(this)));
        (pub, priv) = WOTSPlus.generateKeyPair(seed);
    }

    function _freshKeySet10() internal returns (WOTSPlus.WinternitzAddress[10] memory pubs, bytes32[10] memory privs) {
        for (uint256 i = 0; i < 10; i++) {
            (pubs[i], privs[i]) = _freshKeyPair();
        }
    }

    function _signWith(bytes32 privateKey, bytes32 messageHash)
        internal
        pure
        returns (WOTSPlus.WinternitzElements memory)
    {
        bytes32[67] memory elements = WOTSPlus.sign(privateKey, WOTSPlus.WinternitzMessage({messageHash: messageHash}));
        return WOTSPlus.WinternitzElements({elements: elements});
    }

    /// @dev Pick a currently-live signing key from the named keyset. Scans
    ///      from `seed % live.length` forward, returning the first slot
    ///      whose hash maps to a non-zero priv. Reverts (returns priv=0)
    ///      only if the handler's tracking has drifted — which is itself
    ///      a bug worth surfacing.
    function _pickSigningKey(Codec.KeyType kind, uint256 seed)
        internal
        view
        returns (WOTSPlus.WinternitzAddress memory pub, bytes32 priv)
    {
        WOTSPlus.WinternitzAddress[] memory live = wallet.getKeyset(kind);
        uint256 n = live.length;
        if (n == 0) return (pub, bytes32(0));
        uint256 start = seed % n;
        for (uint256 i = 0; i < n; i++) {
            WOTSPlus.WinternitzAddress memory cand = live[(start + i) % n];
            bytes32 p = (kind == Codec.KeyType.Transaction) ? txnPriv[_keyHash(cand)] : recPriv[_keyHash(cand)];
            if (p != bytes32(0)) {
                return (cand, p);
            }
        }
        return (pub, bytes32(0));
    }

    /// @dev Pick `n` distinct currently-live keys from `kind`'s keyset,
    ///      EXCLUDING `excludeHash`. Walks indices deterministically from
    ///      `seed`. Returns empty array if the live keyset doesn't have
    ///      `n` non-excluded entries.
    function _pickOldKeys(Codec.KeyType kind, uint256 n, uint256 seed, bytes32 excludeHash)
        internal
        view
        returns (WOTSPlus.WinternitzAddress[] memory)
    {
        WOTSPlus.WinternitzAddress[] memory live = wallet.getKeyset(kind);
        uint256 len = live.length;
        if (len < n) return new WOTSPlus.WinternitzAddress[](0);

        WOTSPlus.WinternitzAddress[] memory picks = new WOTSPlus.WinternitzAddress[](n);
        uint256 filled;
        uint256 start = seed % len;
        for (uint256 step = 0; step < len && filled < n; step++) {
            WOTSPlus.WinternitzAddress memory cand = live[(start + step) % len];
            if (_keyHash(cand) == excludeHash) continue;
            picks[filled++] = cand;
        }
        if (filled < n) return new WOTSPlus.WinternitzAddress[](0);
        return picks;
    }

    /*════════════════════════ fuzz entry points ═════════════════════════*/

    /// @dev Tx-signed `execute(target=handler, value, "")`.
    function fuzzExecute(uint256 keyIndex, uint256 valueSeed) external {
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Transaction, keyIndex);
        if (priv == bytes32(0)) return;
        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();

        uint256 walletBal = address(wallet).balance;
        uint256 cap = walletBal > 1 ether ? 1 ether : walletBal;
        uint256 value = cap == 0 ? 0 : valueSeed % (cap + 1);

        bytes32 digest = Codec.executeDigest(
            address(wallet),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            address(this),
            value,
            keccak256(""),
            0
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(priv, digest);

        try wallet.execute(Codec.encodeExecute(cur, nextPub, sig, address(this), value, "")) returns (bytes memory) {
            _consumeTxnKey(cur);
            _installTxnKey(nextPub, nextPriv);
            callsExecute++;
        } catch {
            revertCount++;
        }
    }

    function fuzzWithdrawDepositTo(uint256 keyIndex, uint256 amount) external {
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Transaction, keyIndex);
        if (priv == bytes32(0)) return;
        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();

        bytes32 digest = Codec.withdrawDepositDigest(
            address(wallet),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            address(this),
            amount
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(priv, digest);

        try wallet.withdrawDepositTo(Codec.encodeWithdrawDeposit(cur, nextPub, sig, address(this), amount)) {
            _consumeTxnKey(cur);
            _installTxnKey(nextPub, nextPriv);
            callsWithdraw++;
        } catch {
            revertCount++;
        }
    }

    /*──────────────────────── resetKeyset family ────────────────────────*/

    function fuzzResetKeysetTransaction_recoverySigned(uint256 keyIndex) external {
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Recovery, keyIndex);
        if (priv == bytes32(0)) return;
        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();
        (WOTSPlus.WinternitzAddress[10] memory newPubs, bytes32[10] memory newPrivs) = _freshKeySet10();

        // Snapshot keys to be evicted BEFORE the call so we can clear their
        // priv entries on success without re-querying the wallet.
        WOTSPlus.WinternitzAddress[] memory evicted = wallet.getKeyset(Codec.KeyType.Transaction);

        bytes32 digest = Codec.resetKeysetDigest(
            Codec.KeyType.Transaction,
            Codec.KeyType.Recovery,
            address(wallet),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            keccak256(abi.encode(newPubs))
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(priv, digest);

        try wallet.resetKeyset(
            Codec.encodeResetKeyset(Codec.KeyType.Transaction, Codec.KeyType.Recovery, cur, nextPub, sig, newPubs)
        ) {
            _consumeRecKey(cur);
            _installRecKey(nextPub, nextPriv);
            for (uint256 i = 0; i < evicted.length; i++) {
                _consumeTxnKey(evicted[i]);
            }
            for (uint256 i = 0; i < 10; i++) {
                _installTxnKey(newPubs[i], newPrivs[i]);
            }
            callsResetTxn++;
        } catch {
            revertCount++;
        }
    }

    function fuzzResetKeysetRecovery_txSigned(uint256 keyIndex) external {
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Transaction, keyIndex);
        if (priv == bytes32(0)) return;
        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();
        (WOTSPlus.WinternitzAddress[10] memory newPubs, bytes32[10] memory newPrivs) = _freshKeySet10();

        WOTSPlus.WinternitzAddress[] memory evicted = wallet.getKeyset(Codec.KeyType.Recovery);

        bytes32 digest = Codec.resetKeysetDigest(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            address(wallet),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            keccak256(abi.encode(newPubs))
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(priv, digest);

        try wallet.resetKeyset(
            Codec.encodeResetKeyset(Codec.KeyType.Recovery, Codec.KeyType.Transaction, cur, nextPub, sig, newPubs)
        ) {
            _consumeTxnKey(cur);
            _installTxnKey(nextPub, nextPriv);
            for (uint256 i = 0; i < evicted.length; i++) {
                _consumeRecKey(evicted[i]);
            }
            for (uint256 i = 0; i < 10; i++) {
                _installRecKey(newPubs[i], newPrivs[i]);
            }
            callsResetRec++;
        } catch {
            revertCount++;
        }
    }

    function fuzzResetKeysetVerification_txSigned(uint256 keyIndex) external {
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Transaction, keyIndex);
        if (priv == bytes32(0)) return;
        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();
        (WOTSPlus.WinternitzAddress[10] memory newPubs,) = _freshKeySet10();

        bytes32 digest = Codec.resetKeysetDigest(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            address(wallet),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            keccak256(abi.encode(newPubs))
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(priv, digest);

        try wallet.resetKeyset(
            Codec.encodeResetKeyset(Codec.KeyType.Verification, Codec.KeyType.Transaction, cur, nextPub, sig, newPubs)
        ) {
            _consumeTxnKey(cur);
            _installTxnKey(nextPub, nextPriv);
            // Verification keys aren't priv-tracked, but they are burn-
            // tracked so the monotone invariant catches re-installation.
            for (uint256 i = 0; i < 10; i++) {
                _markEverInstalled(newPubs[i]);
            }
            callsResetVer++;
        } catch {
            revertCount++;
        }
    }

    /*──────────────────────── replaceKeys family ────────────────────────*/

    struct ReplaceArgs {
        Codec.KeyType targetKind;
        Codec.KeyType signingKind;
        uint256 keyIndex;
        uint256 nSeed;
        uint256 oldSeed;
    }

    struct ReplaceMaterial {
        WOTSPlus.WinternitzAddress cur;
        bytes32 priv;
        WOTSPlus.WinternitzAddress nextPub;
        bytes32 nextPriv;
        WOTSPlus.WinternitzAddress[] oldKeys;
        WOTSPlus.WinternitzAddress[] newKeys;
        bytes32[] newPrivs;
    }

    /// @dev Build the signing material + old/new keys for a replaceKeys
    ///      variant. Returns `m.priv == 0` if no signing key is available,
    ///      `m.oldKeys.length == 0` if not enough live target keys remain.
    function _buildReplaceMaterial(ReplaceArgs memory a) internal returns (ReplaceMaterial memory m) {
        (m.cur, m.priv) = _pickSigningKey(a.signingKind, a.keyIndex);
        if (m.priv == bytes32(0)) return m;

        uint256 n = (a.nSeed % 3) + 1; // n ∈ [1, 3]
        bytes32 excludeHash = (a.targetKind == a.signingKind) ? _keyHash(m.cur) : bytes32(0);
        m.oldKeys = _pickOldKeys(a.targetKind, n, a.oldSeed, excludeHash);
        if (m.oldKeys.length == 0) return m;

        (m.nextPub, m.nextPriv) = _freshKeyPair();
        m.newKeys = new WOTSPlus.WinternitzAddress[](n);
        m.newPrivs = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            (m.newKeys[i], m.newPrivs[i]) = _freshKeyPair();
        }
    }

    /// @dev Internal scaffolding for any replaceKeys variant. Pulled out of
    ///      the per-variant fuzz functions to keep their stacks shallow.
    ///      Returns 0 on success, 1 on no-signing-key, 2 on no-old-keys.
    function _doReplaceKeys(ReplaceArgs memory a) internal returns (uint8) {
        ReplaceMaterial memory m = _buildReplaceMaterial(a);
        if (m.priv == bytes32(0)) return 1;
        if (m.oldKeys.length == 0) return 2;

        WOTSPlus.WinternitzElements memory sig = _signWith(
            m.priv,
            Codec.replaceKeysDigest(
                a.targetKind,
                a.signingKind,
                m.oldKeys.length,
                address(wallet),
                block.chainid,
                m.cur.publicSeed,
                m.cur.publicKeyHash,
                m.nextPub.publicSeed,
                m.nextPub.publicKeyHash,
                keccak256(abi.encode(m.oldKeys)),
                keccak256(abi.encode(m.newKeys))
            )
        );

        try wallet.replaceKeys(
            Codec.encodeReplaceKeys(
                a.targetKind, a.signingKind, m.oldKeys.length, m.cur, m.nextPub, sig, m.oldKeys, m.newKeys
            )
        ) {
            _applyReplaceSuccess(a, m);
            return 0;
        } catch {
            revertCount++;
            return 0;
        }
    }

    /// @dev Mirror replaceKeys success state-side. Signing keyset
    ///      always rotates (consume cur, install next). Target keyset
    ///      losses + gains depend on whether target matches signing.
    function _applyReplaceSuccess(ReplaceArgs memory a, ReplaceMaterial memory m) internal {
        // Signing rotation.
        if (a.signingKind == Codec.KeyType.Transaction) {
            _consumeTxnKey(m.cur);
            _installTxnKey(m.nextPub, m.nextPriv);
        } else {
            _consumeRecKey(m.cur);
            _installRecKey(m.nextPub, m.nextPriv);
        }
        // Target rotation.
        for (uint256 i = 0; i < m.oldKeys.length; i++) {
            if (a.targetKind == Codec.KeyType.Transaction) {
                _consumeTxnKey(m.oldKeys[i]);
            } else if (a.targetKind == Codec.KeyType.Recovery) {
                _consumeRecKey(m.oldKeys[i]);
            }
            // Verification has no priv tracking; nothing to consume.
        }
        for (uint256 i = 0; i < m.newKeys.length; i++) {
            if (a.targetKind == Codec.KeyType.Transaction) {
                _installTxnKey(m.newKeys[i], m.newPrivs[i]);
            } else if (a.targetKind == Codec.KeyType.Recovery) {
                _installRecKey(m.newKeys[i], m.newPrivs[i]);
            } else {
                _markEverInstalled(m.newKeys[i]); // Verification
            }
        }
    }

    function fuzzReplaceTxnInTxn(uint256 keyIndex, uint256 nSeed, uint256 oldSeed) external {
        if (
            _doReplaceKeys(ReplaceArgs(Codec.KeyType.Transaction, Codec.KeyType.Transaction, keyIndex, nSeed, oldSeed))
                == 0
        ) callsReplaceTxnInTxn++;
    }

    function fuzzReplaceRecInTxn(uint256 keyIndex, uint256 nSeed, uint256 oldSeed) external {
        if (
            _doReplaceKeys(ReplaceArgs(Codec.KeyType.Recovery, Codec.KeyType.Transaction, keyIndex, nSeed, oldSeed))
                == 0
        ) callsReplaceRecInTxn++;
    }

    function fuzzReplaceVerInTxn(uint256 keyIndex, uint256 nSeed, uint256 oldSeed) external {
        if (
            _doReplaceKeys(ReplaceArgs(Codec.KeyType.Verification, Codec.KeyType.Transaction, keyIndex, nSeed, oldSeed))
                == 0
        ) callsReplaceVerInTxn++;
    }

    function fuzzReplaceTxnInRec(uint256 keyIndex, uint256 nSeed, uint256 oldSeed) external {
        if (
            _doReplaceKeys(ReplaceArgs(Codec.KeyType.Transaction, Codec.KeyType.Recovery, keyIndex, nSeed, oldSeed))
                == 0
        ) callsReplaceTxnInRec++;
    }

    function fuzzReplaceRecInRec(uint256 keyIndex, uint256 nSeed, uint256 oldSeed) external {
        if (_doReplaceKeys(ReplaceArgs(Codec.KeyType.Recovery, Codec.KeyType.Recovery, keyIndex, nSeed, oldSeed)) == 0) callsReplaceRecInRec++;
    }

    function fuzzReplaceVerInRec(uint256 keyIndex, uint256 nSeed, uint256 oldSeed) external {
        if (
            _doReplaceKeys(ReplaceArgs(Codec.KeyType.Verification, Codec.KeyType.Recovery, keyIndex, nSeed, oldSeed))
                == 0
        ) callsReplaceVerInRec++;
    }

    /*──────────── disaster / ownership / upgrade fuzz ops ────────────────*/

    /// @dev Bundle of fresh material for a saveWallet / transferOwnership
    ///      call. Bundled to keep the per-op stack under solc's budget.
    struct ResetBundle {
        WOTSPlus.WinternitzAddress newDis;
        bytes32 newDisPriv;
        WOTSPlus.WinternitzAddress[10] newTxn;
        bytes32[10] newTxnPrivs;
        WOTSPlus.WinternitzAddress[10] newRec;
        bytes32[10] newRecPrivs;
        WOTSPlus.WinternitzAddress[10] newVer;
    }

    function _freshResetBundle() internal returns (ResetBundle memory b) {
        (b.newDis, b.newDisPriv) = _freshKeyPair();
        (b.newTxn, b.newTxnPrivs) = _freshKeySet10();
        (b.newRec, b.newRecPrivs) = _freshKeySet10();
        (b.newVer,) = _freshKeySet10();
    }

    /// @dev Snapshot the pre-call live keyset for both Tx and Rec, store
    ///      in memory arrays so post-success eviction can iterate them
    ///      without relying on `wallet.getKeyset` (which returns the
    ///      POST-call new keys after a successful saveWallet /
    ///      transferOwnership). Returned by `_snapshotEvictees`;
    ///      consumed by `_applyResetBundle`.
    struct Evictees {
        WOTSPlus.WinternitzAddress[] txn;
        WOTSPlus.WinternitzAddress[] rec;
    }

    function _snapshotEvictees() internal view returns (Evictees memory e) {
        e.txn = wallet.getKeyset(Codec.KeyType.Transaction);
        e.rec = wallet.getKeyset(Codec.KeyType.Recovery);
    }

    /// @dev Apply reset-bundle's state changes (disaster rotation + full
    ///      keyset replace) to handler tracking after a successful
    ///      saveWallet. `e` carries the PRE-call snapshot of evictees.
    function _applyResetBundle(ResetBundle memory b, Evictees memory e) internal {
        disasterPub = b.newDis;
        disasterPriv = b.newDisPriv;
        _markEverInstalled(b.newDis);
        for (uint256 i = 0; i < e.txn.length; i++) {
            _consumeTxnKey(e.txn[i]);
        }
        for (uint256 i = 0; i < e.rec.length; i++) {
            _consumeRecKey(e.rec[i]);
        }
        for (uint256 i = 0; i < 10; i++) {
            _installTxnKey(b.newTxn[i], b.newTxnPrivs[i]);
            _installRecKey(b.newRec[i], b.newRecPrivs[i]);
            _markEverInstalled(b.newVer[i]);
        }
    }

    /// @dev Disaster-key-signed full keyset reset. Rotates the disaster
    ///      key in its own storage slot and wipes-then-reinstalls all
    ///      three keysets at 10 entries each.
    function fuzzSaveWallet() external {
        if (disasterPriv == bytes32(0)) return;
        ResetBundle memory b = _freshResetBundle();
        bytes memory pmd = _signSaveWallet(b);
        Evictees memory e = _snapshotEvictees();
        try wallet.saveWallet(pmd) {
            _applyResetBundle(b, e);
            callsSaveWallet++;
        } catch {
            revertCount++;
        }
    }

    function _signSaveWallet(ResetBundle memory b) internal view returns (bytes memory) {
        bytes32 keysHash = keccak256(abi.encode(b.newTxn, b.newRec, b.newVer));
        bytes32 digest = Codec.saveWalletDigest(
            address(wallet),
            block.chainid,
            disasterPub.publicSeed,
            disasterPub.publicKeyHash,
            b.newDis.publicSeed,
            b.newDis.publicKeyHash,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(disasterPriv, digest);
        return Codec.encodeSaveWallet(disasterPub, b.newDis, sig, b.newTxn, b.newRec, b.newVer);
    }

    /// @dev Ownership-key-signed atomic reinit. Forces `newOwner =
    ///      address(this)` so the handler stays owner across the call
    ///      and can keep fuzzing. Rotates ownership + disaster (single
    ///      slots) and the three keysets (10 each).
    function fuzzTransferOwnership() external {
        if (ownershipPriv == bytes32(0)) return;
        (WOTSPlus.WinternitzAddress memory newOwn, bytes32 newOwnPriv) = _freshKeyPair();
        ResetBundle memory b = _freshResetBundle();
        bytes memory pmd = _signTransferOwnership(newOwn, b);
        Evictees memory e = _snapshotEvictees();
        try wallet.transferOwnership(pmd) {
            ownershipPub = newOwn;
            ownershipPriv = newOwnPriv;
            _markEverInstalled(newOwn);
            _applyResetBundle(b, e);
            callsTransferOwnership++;
        } catch {
            revertCount++;
        }
    }

    function _signTransferOwnership(WOTSPlus.WinternitzAddress memory newOwn, ResetBundle memory b)
        internal
        view
        returns (bytes memory)
    {
        bytes32 keysHash = keccak256(abi.encode(b.newDis, b.newTxn, b.newRec, b.newVer));
        bytes32 digest = Codec.transferOwnershipDigest(
            address(wallet),
            block.chainid,
            ownershipPub.publicSeed,
            ownershipPub.publicKeyHash,
            newOwn.publicSeed,
            newOwn.publicKeyHash,
            address(this),
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _signWith(ownershipPriv, digest);
        return
            Codec.encodeOwnershipTransfer(
                ownershipPub, newOwn, sig, address(this), b.newDis, b.newTxn, b.newRec, b.newVer
            );
    }

    /// @dev Tx-signed UUPS upgrade to a different vetted impl. Migration
    ///      flag forced false — the migrator payload is 2048 zero bytes
    ///      and unused. Only the impl slot changes; keyset state
    ///      preserved. Rotates one transaction key.
    function fuzzUpgradeToAndCall(uint256 keyIndex, uint256 implIndex) external {
        address newImpl = _pickDifferentImpl(implIndex);
        if (newImpl == address(0)) return;
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Transaction, keyIndex);
        if (priv == bytes32(0)) return;

        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();

        bytes memory upgradeData = _buildUpgradeData(newImpl, cur, nextPub, priv);

        try wallet.upgradeToAndCall(newImpl, upgradeData) {
            _consumeTxnKey(cur);
            _installTxnKey(nextPub, nextPriv);
            callsUpgradeToAndCall++;
        } catch {
            revertCount++;
        }
    }

    /// @dev Recovery-signed UUPS upgrade. Like `upgradeToAndCall` but
    ///      authorized by a recovery key and with no migration support
    ///      in the codec — a simpler envelope.
    function fuzzRecoveryUpgrade(uint256 keyIndex, uint256 implIndex) external {
        address newImpl = _pickDifferentImpl(implIndex);
        if (newImpl == address(0)) return;
        (WOTSPlus.WinternitzAddress memory cur, bytes32 priv) = _pickSigningKey(Codec.KeyType.Recovery, keyIndex);
        if (priv == bytes32(0)) return;

        (WOTSPlus.WinternitzAddress memory nextPub, bytes32 nextPriv) = _freshKeyPair();

        bytes32 digest = Codec.upgradeRecoveryDigest(
            address(wallet),
            block.chainid,
            newImpl,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory pqSig = _signWith(priv, digest);

        // Verifier proves the new impl can run — fresh keypair signs a
        // verificationDigest over the new impl. Same shape as
        // `upgradeToAndCall`'s verifier.
        (WOTSPlus.WinternitzAddress memory verifierPub, bytes32 verifierPriv) = _freshKeyPair();
        bytes32 vDigest = Codec.verificationDigest(
            address(wallet), block.chainid, newImpl, verifierPub.publicSeed, verifierPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _signWith(verifierPriv, vDigest);

        try wallet.recoveryUpgrade(newImpl, Codec.encodeRecoveryUpgrade(cur, nextPub, pqSig, verifierPub, vSig)) {
            _consumeRecKey(cur);
            _installRecKey(nextPub, nextPriv);
            callsRecoveryUpgrade++;
        } catch {
            revertCount++;
        }
    }

    /*══════════════════════ upgrade helpers ═════════════════════════════*/

    function _pickDifferentImpl(uint256 implIndex) internal view returns (address) {
        if (vettedImpls.length < 2) return address(0);
        address current = address(uint160(uint256(vm.load(address(wallet), _ERC1967_IMPLEMENTATION_SLOT))));
        uint256 start = implIndex % vettedImpls.length;
        for (uint256 i = 0; i < vettedImpls.length; i++) {
            address cand = vettedImpls[(start + i) % vettedImpls.length];
            if (cand != current) return cand;
        }
        return address(0);
    }

    function _buildUpgradeData(
        address newImpl,
        WOTSPlus.WinternitzAddress memory cur,
        WOTSPlus.WinternitzAddress memory nextPub,
        bytes32 priv
    ) internal returns (bytes memory) {
        // Migrator payload: 2048 zero bytes. `shouldMigrate=false` so
        // the wallet never decodes or delegatecalls into this section.
        bytes memory dummyMigrator = new bytes(2048);

        bytes32 digest = Codec.upgradeDigest(
            address(wallet),
            block.chainid,
            newImpl,
            cur.publicSeed,
            cur.publicKeyHash,
            nextPub.publicSeed,
            nextPub.publicKeyHash,
            false,
            keccak256(dummyMigrator)
        );
        WOTSPlus.WinternitzElements memory pqSig = _signWith(priv, digest);

        (WOTSPlus.WinternitzAddress memory verifierPub, bytes32 verifierPriv) = _freshKeyPair();
        bytes32 vDigest = Codec.verificationDigest(
            address(wallet), block.chainid, newImpl, verifierPub.publicSeed, verifierPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _signWith(verifierPriv, vDigest);

        return
            Codec.encodeUpgradeToAndCall(
                cur,
                nextPub,
                pqSig,
                verifierPub,
                vSig,
                false,
                dummyMigrator
            );
    }

    /*════════════════════════ view helpers ══════════════════════════════*/

    function everInstalledCount() external view returns (uint256) {
        return everInstalled.length;
    }

    function everInstalledAt(uint256 i) external view returns (WOTSPlus.WinternitzAddress memory) {
        return everInstalled[i];
    }

    function totalSuccessfulCalls() external view returns (uint256) {
        return callsExecute + callsWithdraw + callsResetTxn + callsResetRec + callsResetVer + callsReplaceTxnInTxn
            + callsReplaceRecInTxn + callsReplaceVerInTxn + callsReplaceTxnInRec + callsReplaceRecInRec
            + callsReplaceVerInRec + callsSaveWallet + callsTransferOwnership + callsUpgradeToAndCall
            + callsRecoveryUpgrade;
    }

    function vettedImplsCount() external view returns (uint256) {
        return vettedImpls.length;
    }

    function vettedImplAt(uint256 i) external view returns (address) {
        return vettedImpls[i];
    }
}
