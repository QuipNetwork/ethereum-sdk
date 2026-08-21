// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../../../WalletFactory/WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusImplementationInvariantHandler} from "./Handler.t.sol";

/// @title WOTSPlusImplementation Invariant Test Base
/// @dev Deploys a fresh wallet whose owner is the fuzz Handler so onlyOwner
///      calls require no pranking. Hands the Handler the full set of
///      initial signing material (txn privs, rec privs, disaster priv,
///      ownership priv) plus a list of vetted implementations so the
///      upgrade-flow fuzz selectors can rotate among them. Subclasses
///      declare `invariant_*` functions and call
///      `targetContract(address(handler))` from their own `setUp` after
///      `super.setUp()`.
abstract contract WOTSPlusImplementationInvariantBase is WalletFactoryTest {
    WOTSPlusImplementationInvariantHandler public handler;
    WOTSPlusImplementation public wallet;
    WOTSPlusImplementation internal secondImpl;

    bytes32 internal constant INVARIANT_VAULT_SEED = "handler-vault";
    uint256 internal constant INVARIANT_INITIAL_DEPOSIT = 100 ether;

    function setUp() public virtual override {
        super.setUp();

        // Deploy handler first so its address is known when we deploy the
        // wallet with `owner = address(handler)`.
        handler = new WOTSPlusImplementationInvariantHandler();
        vm.deal(address(handler), INVARIANT_INITIAL_DEPOSIT + 10 ether);

        bytes memory payload = _buildAndDeployWallet();
        (payload); // silence unused warning; helper has side effects we need

        // Deploy and vet a second WOTSPlusImplementation implementation so
        // `fuzzUpgradeToAndCall` / `fuzzRecoveryUpgrade` have something
        // to rotate to. The first impl was deployed by the factory at
        // its own setUp; we read it via `_currentImpl()` after wallet
        // deployment.
        secondImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        _initializeHandler();
    }

    /// @dev Generates the canonical seeded key material, builds the init
    ///      payload, and deploys the wallet via the factory under the
    ///      handler's prank. Returns the encoded payload bytes (unused
    ///      but kept for symmetry with `_buildInitPayloadForCreate`).
    function _buildAndDeployWallet() internal returns (bytes memory) {
        (WOTSPlus.WinternitzAddress[10] memory txnPubs, bytes32[10] memory txnPrivs) =
            _generateTransactionKeys(INVARIANT_VAULT_SEED);

        WOTSPlus.WinternitzAddress[] memory recArr = _generateRecoveryKeys(txnPrivs[0], 10);

        bytes memory payload = _buildInitPayloadForCreate(INVARIANT_VAULT_SEED, txnPubs, recArr);

        vm.prank(address(handler));
        address walletAddr = factory.deployLatestWalletProxy{value: INVARIANT_INITIAL_DEPOSIT}(keccak256(abi.encodePacked(INVARIANT_VAULT_SEED)), COMMITMENT, payable(address(handler)), payload
        );
        wallet = WOTSPlusImplementation(payable(walletAddr));
        return payload;
    }

    /// @dev Rebuilds the seeded key material (cheap — pure functions over
    ///      the deterministic vault seed) and hands it to the handler in
    ///      one struct. Split out of `setUp()` to keep the parent frame's
    ///      stack within Solidity's local-variable budget; reconstructing
    ///      the material here is cheaper than carrying ~80 stack slots.
    function _initializeHandler() internal {
        (WOTSPlus.WinternitzAddress[10] memory txnPubs, bytes32[10] memory txnPrivs) =
            _generateTransactionKeys(INVARIANT_VAULT_SEED);

        WOTSPlus.WinternitzAddress[] memory recArr = _generateRecoveryKeys(txnPrivs[0], 10);
        WOTSPlus.WinternitzAddress[10] memory recPubs;
        bytes32[10] memory recPrivs;
        for (uint256 i = 0; i < 10; i++) {
            recPubs[i] = recArr[i];
            recPrivs[i] = _recoverySigningKey(txnPrivs[0], i);
        }

        (WOTSPlus.WinternitzAddress[10] memory verPubs,) = _generateVerificationKeys(INVARIANT_VAULT_SEED);

        (WOTSPlus.WinternitzAddress memory disasterPub, bytes32 disasterPriv) =
            _generateDisasterRecoveryKey(INVARIANT_VAULT_SEED);
        (WOTSPlus.WinternitzAddress memory ownershipPub, bytes32 ownershipPriv) =
            _generateOwnershipKey(INVARIANT_VAULT_SEED);

        address[] memory impls = new address[](2);
        impls[0] = _currentImpl();
        impls[1] = address(secondImpl);

        handler.initialize(
            WOTSPlusImplementationInvariantHandler.InitParams({
                wallet: wallet,
                txnPubs: txnPubs,
                txnPrivs: txnPrivs,
                recPubs: recPubs,
                recPrivs: recPrivs,
                verPubs: verPubs,
                disasterPub: disasterPub,
                disasterPriv: disasterPriv,
                ownershipPub: ownershipPub,
                ownershipPriv: ownershipPriv,
                vettedImpls: impls
            })
        );
    }

    /// @dev Reads the ERC-1967 implementation slot of the deployed wallet
    ///      proxy. Used to seed the handler's vetted-impl list with the
    ///      currently-installed impl alongside `secondImpl`.
    function _currentImpl() internal view returns (address) {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        return address(uint160(uint256(vm.load(address(wallet), slot))));
    }

    /// @dev Override the inherited `test_setUp` from WalletFactoryTest. The
    ///      parent asserts `getVettedCodeCount() == 1`, but the invariant
    ///      base vets a second impl for the upgrade-flow fuzz selectors.
    ///      Re-asserts the parent's other checks and adjusts the count.
    function test_setUp() public view override {
        assertEq(factory.owner(), ADMIN);
        assertEq(factory.creationFee(), 0);
        assertEq(factory.executeFee(), 0);
        assertEq(factory.MAX_FEE(), 0.1 ether);
        assertEq(factory.getVettedCodeCount(), 2);
    }

    /*════════════════════════ shared invariants ═════════════════════════
     *
     * Declared once on the base; both `Local` and `LocalHeavy` inherit
     * them. Each invariant fires independently in each suite, so a
     * property violation triggered ONLY by an op in one selector
     * partition pinpoints itself to that suite. Trivially-true cases
     * (e.g., `implementationIsVetted` in the light suite, which never
     * rotates the impl) cost one external call per run — negligible.
     *
     * ─────────────────────────────────────────────────────────────────*/

    /// @dev INVARIANTS.md §5 — every signed primitive must preserve the
    ///      always-10 size of every keyset.
    function invariant_keysetSizesAlwaysTen() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10, "Transaction keyset broke always-10");
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10, "Recovery keyset broke always-10");
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10, "Verification keyset broke always-10");
    }

    /// @dev INVARIANTS.md §5 — no key may appear in more than one keyset
    ///      simultaneously. Pairwise check across all three keysets.
    function invariant_noKeyAppearsInTwoKeysets() public view {
        WOTSPlus.WinternitzAddress[] memory txn = wallet.getKeyset(Codec.KeyType.Transaction);
        WOTSPlus.WinternitzAddress[] memory rec = wallet.getKeyset(Codec.KeyType.Recovery);
        WOTSPlus.WinternitzAddress[] memory ver = wallet.getKeyset(Codec.KeyType.Verification);
        _assertDisjoint(txn, rec, "txn-rec");
        _assertDisjoint(txn, ver, "txn-ver");
        _assertDisjoint(rec, ver, "rec-ver");
    }

    /// @dev INVARIANTS.md §1, §5 — once a key has been installed in any
    ///      keyset, `isKeySpent` must stay true for it forever. Walks
    ///      the entire `everInstalled` log; cost is ~3k gas per entry
    ///      and the log grows to O(20k) over a full campaign, so this
    ///      adds a few seconds to wall time but covers every install
    ///      the handler has ever performed.
    function invariant_burnSetMonotone() public view {
        uint256 total = handler.everInstalledCount();
        for (uint256 i = 0; i < total; i++) {
            WOTSPlus.WinternitzAddress memory k = handler.everInstalledAt(i);
            assertTrue(wallet.isKeySpent(k), "burn-set dropped a historical key");
        }
    }

    /// @dev INVARIANTS.md §10 — disaster and ownership keys stay non-zero
    ///      at every boundary. Zero would break WOTS+ verification on the
    ///      next disaster / ownership-signed call.
    function invariant_disasterAndOwnershipKeysNonZero() public view {
        WOTSPlus.WinternitzAddress memory dis = wallet.getDisasterRecoveryKey();
        WOTSPlus.WinternitzAddress memory own = wallet.getOwnershipKey();
        assertTrue(dis.publicSeed != bytes32(0), "disaster seed zeroed");
        assertTrue(dis.publicKeyHash != bytes32(0), "disaster hash zeroed");
        assertTrue(own.publicSeed != bytes32(0), "ownership seed zeroed");
        assertTrue(own.publicKeyHash != bytes32(0), "ownership hash zeroed");
    }

    /// @dev `quipFactory` is set in initialize and never mutated.
    function invariant_factoryAddressUnchanged() public view {
        assertEq(address(wallet.quipFactory()), address(factory));
    }

    /// @dev INVARIANTS.md §7 — the ERC-1967 implementation slot must
    ///      always point at a factory-vetted address. Trivially true in
    ///      the light suite (no upgrade ops); meaningful in the heavy
    ///      suite where `fuzzUpgradeToAndCall` / `fuzzRecoveryUpgrade`
    ///      rotate the impl among vetted candidates.
    function invariant_implementationIsVetted() public view {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        address impl = address(uint160(uint256(vm.load(address(wallet), slot))));
        uint256 count = handler.vettedImplsCount();
        for (uint256 i = 0; i < count; i++) {
            if (handler.vettedImplAt(i) == impl) return;
        }
        assertTrue(false, "implementation not in vetted set");
    }

    /// @dev The classical owner. `transferOwnership` rotates it, but the
    ///      handler always passes `newOwner = address(this)`, so across
    ///      the entire campaign the owner must stay equal to the handler.
    ///      If this ever fires, the handler's fuzz selectors cannot
    ///      proceed (every call would revert with Unauthorized), and the
    ///      campaign is silently degenerate from that point on.
    function invariant_ownerStaysHandler() public view {
        assertEq(wallet.owner(), address(handler), "owner drifted away");
    }

    /// @dev INVARIANTS.md §5 — every keyset member must have BOTH fields
    ///      non-zero. The always-10 + disjoint invariants don't catch
    ///      `{0, 0}` injection because zero is a valid bytes32 value;
    ///      this pins the explicit non-zero clause.
    function invariant_keysetMembersHaveNonZeroFields() public view {
        _assertAllNonZero(wallet.getKeyset(Codec.KeyType.Transaction));
        _assertAllNonZero(wallet.getKeyset(Codec.KeyType.Recovery));
        _assertAllNonZero(wallet.getKeyset(Codec.KeyType.Verification));
    }

    /// @dev INVARIANTS.md §1, §5 — reverse direction of
    ///      `burnSetMonotone`: every currently-live key MUST be in the
    ///      burn set. Pins the structural invariant that `_safeAddKey`
    ///      always calls `_markKeySpent`.
    function invariant_currentKeysetMembersAreInBurnSet() public view {
        _assertAllInBurnSet(wallet.getKeyset(Codec.KeyType.Transaction));
        _assertAllInBurnSet(wallet.getKeyset(Codec.KeyType.Recovery));
        _assertAllInBurnSet(wallet.getKeyset(Codec.KeyType.Verification));
    }

    /*════════════════════════ assertion helpers ═════════════════════════*/

    function _assertDisjoint(
        WOTSPlus.WinternitzAddress[] memory a,
        WOTSPlus.WinternitzAddress[] memory b,
        string memory label
    ) internal pure {
        for (uint256 i = 0; i < a.length; i++) {
            bytes32 ah = keccak256(abi.encode(a[i]));
            for (uint256 j = 0; j < b.length; j++) {
                bytes32 bh = keccak256(abi.encode(b[j]));
                if (ah == bh) {
                    revert(string.concat("disjoint violated: ", label));
                }
            }
        }
    }

    function _assertAllNonZero(WOTSPlus.WinternitzAddress[] memory keys) internal pure {
        for (uint256 i = 0; i < keys.length; i++) {
            assertTrue(keys[i].publicSeed != bytes32(0), "key publicSeed is zero");
            assertTrue(keys[i].publicKeyHash != bytes32(0), "key publicKeyHash is zero");
        }
    }

    function _assertAllInBurnSet(WOTSPlus.WinternitzAddress[] memory keys) internal view {
        for (uint256 i = 0; i < keys.length; i++) {
            assertTrue(wallet.isKeySpent(keys[i]), "live key not in burn set");
        }
    }
}
