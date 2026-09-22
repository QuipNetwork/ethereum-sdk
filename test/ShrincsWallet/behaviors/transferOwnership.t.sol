// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev A contract recipient of a handover: accepts exactly the digests it was told to.
contract AcceptingContractOwner {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    mapping(bytes32 => bool) public accepted;

    function accept(bytes32 digest) external {
        accepted[digest] = true;
    }

    function isValidSignature(bytes32 digest, bytes calldata) external view returns (bytes4) {
        return accepted[digest] ? MAGIC : bytes4(0);
    }
}

/// @dev Behavior tests for the atomic ownership-handover `transferOwnership`. Access control, input
///      validation, and the stateless-rotate `InvalidSignature` branch are covered, plus the full
///      four-signature happy path — the current owner's stateless recovery rotation AND stateful
///      owner-binding signature over `(newOwner, nextCommitment)`, and the incoming party's hybrid
///      acceptance (`newOwner`'s ECDSA / ERC-1271 signature AND a stateful signature from the
///      incoming bundle itself) — with each signature's binding checked in isolation. All signed live.
contract ShrincsWallet_transferOwnership is ShrincsWalletTest {
    address internal NEW_OWNER;
    uint256 internal NEW_OWNER_PK;
    // The acceptance leaf the incoming bundle signs with (any leaf in `[1, MAX_SIG]`).
    uint32 internal constant ACCEPT_LEAF = 1;
    address internal constant TARGET = address(0xBEEF);

    function setUp() public virtual override {
        super.setUp();
        (NEW_OWNER, NEW_OWNER_PK) = makeAddrAndKey("newOwner");
    }

    function test_setUp() public view virtual override {
        super.test_setUp();
        assertEq(vm.addr(NEW_OWNER_PK), NEW_OWNER, "recipient key pair");
        assertTrue(NEW_OWNER != OWNER, "recipient is a distinct party");
        assertEq(NEW_OWNER.code.length, 0, "recipient is an EOA");
    }

    /*──────────────────── helpers ────────────────────*/

    /// @dev A fresh next-key bundle plus its signing key (the recipient's).
    function _nextKey() internal view returns (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) {
        (nextKey, key) = _makeRotationTarget("transfer-ownership-next-key");
    }

    /// @dev Stateful owner-binding signature cross-binding `newOwner` to the incoming bundle.
    function _ownerBindingSig(address newOwner, bytes32 nextCommitment)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        return _signStatefulAction(
            Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(newOwner, nextCommitment), 1
        );
    }

    /// @dev Both current-owner signatures for handing `nextKey` to `newOwner`.
    function _currentOwnerSigs(SHRINCS.RotationTarget memory nextKey, address newOwner)
        internal
        returns (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig)
    {
        recoverySig = _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        ownerSig = _ownerBindingSig(newOwner, _toBytes32(nextKey.publicKeyCommitment));
    }

    /// @dev Both halves of the recipient's acceptance for `nextKey` going to `newOwner`.
    function _acceptance(SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key, address newOwner, uint256 pk)
        internal
        view
        returns (SHRINCS.Signature memory keyAcceptance, bytes memory ownerAcceptance)
    {
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        keyAcceptance = _signKeyAcceptance(key, c, newOwner, ACCEPT_LEAF);
        ownerAcceptance = _signOwnerAcceptance(pk, newOwner, c);
    }

    /// @dev Full, valid handover of a fresh bundle to NEW_OWNER, submitted by OWNER.
    function _handover() internal returns (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) {
        (nextKey, key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);
        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, ownerAcc);
    }

    /*──────────────────── access / input ────────────────────*/

    function test_transferOwnership_revertsWhen_notOwner() public {
        SHRINCS.Signature memory ownerSig;
        SPHINCSPlusC.Signature memory recoverySig;
        SHRINCS.RotationTarget memory nextKey;
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, ownerSig, "");
    }

    function test_transferOwnership_revertsWhen_zeroOwner() public {
        SHRINCS.Signature memory ownerSig;
        SPHINCSPlusC.Signature memory recoverySig;
        SHRINCS.RotationTarget memory nextKey;
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroAddressOwner.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, address(0), ownerSig, "");
    }

    function test_transferOwnership_revertsWhen_invalidRecoverySignature() public {
        // An empty recovery signature makes `statelessRotate` return the zero commitment,
        // surfaced as InvalidSignature.
        SHRINCS.Signature memory ownerSig;
        SPHINCSPlusC.Signature memory recoverySig;
        (SHRINCS.RotationTarget memory nextKey,) = _nextKey();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, ownerSig, "");
    }

    /*──────────────────── happy path ────────────────────*/

    function test_transferOwnership_fullHandover() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);
        uint256 nonceBefore = wallet.actionNonce();

        vm.prank(OWNER);
        vm.expectEmit(true, true, true, true, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(ACCEPT_LEAF, 1);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, ownerAcc);

        assertEq(wallet.owner(), NEW_OWNER, "classical owner handed over");
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "fresh bundle installed for the new owner");
        assertEq(factory.walletOwner(address(wallet)), NEW_OWNER, "factory registry synced");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        // Two current-key signatures consumed (stateful owner-binding + stateless rotation), both
        // bound to the pre-call nonce — nets exactly +2. The acceptance binds no nonce.
        assertEq(wallet.actionNonce(), nonceBefore + 2, "handover consumes two current-key signatures");
        // The incoming bundle's acceptance leaf opened the new epoch already spent.
        assertTrue(wallet.isStatefulLeafUsed(ACCEPT_LEAF), "acceptance leaf spent in the new epoch");
        assertFalse(wallet.isStatefulLeafUsed(ACCEPT_LEAF + 1), "only the acceptance leaf is spent");
        assertEq(wallet.statefulLeavesUsed(), 1, "new epoch counter starts at the acceptance leaf");
    }

    /// @dev After the handover the recipient operates the wallet with a fresh leaf, and the
    ///      acceptance leaf can never sign again — its one-time key already signed a public message.
    function test_transferOwnership_newOwnerOperatesWithFreshLeaf_acceptanceLeafReplayRejected() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _handover();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        SHRINCS.PublicKey memory nextPk = _bundleOf(nextKey);
        bytes32 payloadHash = Codec.executePayloadHash(TARGET, 0, keccak256(""), 0);

        // Replaying the acceptance leaf under the live context is a stale leaf.
        SHRINCS.Signature memory replay =
            _signStatefulActionWith(key, c, _actionContext(Codec.ACTION_EXECUTE, payloadHash), ACCEPT_LEAF);
        vm.prank(NEW_OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.execute(nextPk, replay, TARGET, 0, "", 0);

        // A fresh leaf works: the recipient holds both halves of the gate.
        SHRINCS.Signature memory fresh =
            _signStatefulActionWith(key, c, _actionContext(Codec.ACTION_EXECUTE, payloadHash), ACCEPT_LEAF + 1);
        vm.prank(NEW_OWNER);
        wallet.execute(nextPk, fresh, TARGET, 0, "", 0);
        assertEq(wallet.statefulLeavesUsed(), 2);
    }

    /// @dev The new epoch's leaf counter restarts at the acceptance leaf even when the
    ///      previous epoch consumed leaves: without the reset, pre-handover consumption would
    ///      leak into the new epoch's budget (the bitmap namespace is fresh but the counter is
    ///      not), short-changing the new owner.
    function test_transferOwnership_handoverResetsLeafCounterToAcceptanceLeaf() public {
        // Dirty the counter first — without prior consumption it already reads 1 at handover
        // time and the reset is a silent no-op.
        bytes32 payloadHash = Codec.executePayloadHash(TARGET, 0, keccak256(""), 0);
        SHRINCS.Signature memory executeSig = _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 2);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), executeSig, TARGET, 0, "", 0);
        assertEq(wallet.statefulLeavesUsed(), 1, "one leaf consumed before handover");

        _handover();

        assertEq(wallet.statefulLeavesUsed(), 1, "new epoch counter restarts at the acceptance leaf");
        assertTrue(wallet.isStatefulLeafUsed(ACCEPT_LEAF), "acceptance leaf spent in the new epoch");
    }

    /// @dev The acceptance binds neither nonce nor epoch: the recipient can sign it long before the
    ///      current owner broadcasts, and any actions the current owner consumes in between do not
    ///      invalidate it. (The commitment can be installed once, so it cannot be replayed either.)
    function test_transferOwnership_acceptanceSurvivesInterveningOwnerActions() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);

        // The current owner consumes a leaf (nonce +1) after the recipient signed.
        bytes32 payloadHash = Codec.executePayloadHash(TARGET, 0, keccak256(""), 0);
        SHRINCS.Signature memory executeSig = _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 2);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), executeSig, TARGET, 0, "", 0);
        uint256 nonceAfterExecute = wallet.actionNonce();

        // Current-owner signatures are produced against the LIVE state; the acceptance is reused as is.
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, ownerAcc);
        assertEq(wallet.owner(), NEW_OWNER);
        assertEq(wallet.actionNonce(), nonceAfterExecute + 2);
    }

    /*──────────────────── current-owner signature bindings ────────────────────*/

    function test_transferOwnership_crossBindingMismatch() public {
        // The stateless rotation succeeds, but a `newOwner` not matching the stateful owner-binding
        // signature's `(newOwner, nextCommitment)` payload fails verification.
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, makeAddr("wrongOwner"), keyAcc, ownerAcc);
    }

    /// @dev The recovery→handover direction: a recovery signature signed for `recoverWallet`
    ///      must NOT serve as the recovery half of a handover bundle — rejected by the tagged
    ///      rotation domain (independently of the other signatures, which are all valid
    ///      here to isolate what is being tested).
    function test_transferOwnership_revertsWhen_signatureSignedForRecoverWallet() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, nextCommitment);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, ownerAcc);
    }

    /*──────────────────── recipient acceptance: classical half ────────────────────*/

    /// @dev The audit scenario: the current owner's signatures are all valid for a `newOwner` that
    ///      is a typo. Nobody can sign the acceptance for that address, so the handover reverts —
    ///      previously it completed and stranded the wallet behind an owner that does not exist.
    function test_transferOwnership_revertsWhen_newOwnerMistyped() public {
        address typo = makeAddr("newOwner-typo");
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, typo);
        // The intended recipient signed for their own address; the bundle acceptance names the typo
        // so only the classical half is under test.
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(key, _toBytes32(nextKey.publicKeyCommitment), typo, ACCEPT_LEAF);
        bytes memory ownerAcc = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, _toBytes32(nextKey.publicKeyCommitment));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, typo, keyAcc, ownerAcc);
        assertEq(wallet.owner(), OWNER, "handover rolled back");
        assertEq(wallet.keyVersion(), 0, "no bundle installed");
    }

    function test_transferOwnership_revertsWhen_ownerAcceptanceEmpty() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc,) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, "");
    }

    /// @dev The current owner cannot forge the recipient's acceptance.
    function test_transferOwnership_revertsWhen_ownerAcceptanceSignedByCurrentOwner() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc,) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);
        bytes memory forged = _signOwnerAcceptance(OWNER_PK, NEW_OWNER, _toBytes32(nextKey.publicKeyCommitment));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, forged);
    }

    /// @dev An acceptance is for ONE bundle: it cannot be reused to accept a different one.
    function test_transferOwnership_revertsWhen_ownerAcceptanceBoundToOtherBundle() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.RotationTarget memory other,) = _makeRotationTarget("transfer-ownership-other-bundle");
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc,) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);
        bytes memory forOther = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, _toBytes32(other.publicKeyCommitment));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, forOther);
    }

    /// @dev Domain separation: a signature the recipient produced under the wallet's OTHER ECDSA
    ///      surface (the userOp co-signature target) over the same payload hash is not an
    ///      acceptance.
    function test_transferOwnership_revertsWhen_ownerAcceptanceUnderOtherTypehash() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc,) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(NEW_OWNER_PK, wallet.quipUserOpHashEcdsaTarget(Codec.transferOwnershipPayloadHash(NEW_OWNER, c)));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, abi.encodePacked(r, s, v));
    }

    function test_transferOwnership_contractRecipient_acceptsViaErc1271() public {
        AcceptingContractOwner recipient = new AcceptingContractOwner();
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        recipient.accept(wallet.quipSignedHashEcdsaTarget(Codec.transferOwnershipPayloadHash(address(recipient), c)));
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, address(recipient));
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(key, c, address(recipient), ACCEPT_LEAF);

        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, address(recipient), keyAcc, "");
        assertEq(wallet.owner(), address(recipient));
        assertEq(factory.walletOwner(address(wallet)), address(recipient));
    }

    function test_transferOwnership_contractRecipient_revertsWhen_notAccepting() public {
        AcceptingContractOwner recipient = new AcceptingContractOwner();
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, address(recipient));
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(key, c, address(recipient), ACCEPT_LEAF);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, address(recipient), keyAcc, "");
    }

    /*──────────────────── recipient acceptance: PQ half ────────────────────*/

    function test_transferOwnership_revertsWhen_keyAcceptanceEmpty() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);
        SHRINCS.Signature memory empty;

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, empty, ownerAcc);
    }

    function test_transferOwnership_revertsWhen_keyAcceptanceLeafOverBudget() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        (, bytes memory ownerAcc) = _acceptance(nextKey, key, NEW_OWNER, NEW_OWNER_PK);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.transferOwnership(
            _mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, _statefulSigWithLeaf(MAX_SIG + 1), ownerAcc
        );
    }

    /// @dev The current key cannot stand in for the incoming one: the acceptance must verify
    ///      against `nextCommitment`.
    function test_transferOwnership_revertsWhen_keyAcceptanceSignedByCurrentKey() public {
        (SHRINCS.RotationTarget memory nextKey,) = _nextKey();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        bytes memory ownerAcc = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, c);
        SHRINCS.Signature memory byCurrent = _signKeyAcceptance(mainKey, c, NEW_OWNER, SIGN_BASE + 3);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, byCurrent, ownerAcc);
    }

    /// @dev The acceptance context is fixed at nonce 0 / epoch 0: a signature by the incoming key
    ///      under the wallet's LIVE nonce and epoch is not an acceptance (and could never be
    ///      confused with one of its own actions after install, which carry nonce >= 2 / epoch >= 1).
    function test_transferOwnership_revertsWhen_keyAcceptanceUnderLiveContext() public {
        // Move the wallet off nonce 0 first — on a fresh wallet the live context IS (0, 0).
        bytes32 executeHash = Codec.executePayloadHash(TARGET, 0, keccak256(""), 0);
        SHRINCS.Signature memory executeSig = _signStatefulAction(Codec.ACTION_EXECUTE, executeHash, 2);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), executeSig, TARGET, 0, "", 0);
        assertEq(wallet.actionNonce(), 1);

        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        bytes memory ownerAcc = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, c);
        SHRINCS.Signature memory keyAcc = _signStatefulActionWith(
            key, c, _actionContext(Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(NEW_OWNER, c)), ACCEPT_LEAF
        );

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, ownerAcc);
    }

    /// @dev The bundle acceptance names the owner too: the pair `(newOwner, bundle)` is what the
    ///      recipient accepts, so the same bundle cannot be handed to a different address.
    function test_transferOwnership_revertsWhen_keyAcceptanceForOtherOwner() public {
        (SHRINCS.RotationTarget memory nextKey, SHRINCS.SigningKey memory key) = _nextKey();
        bytes32 c = _toBytes32(nextKey.publicKeyCommitment);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(nextKey, NEW_OWNER);
        bytes memory ownerAcc = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, c);
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(key, c, makeAddr("someone-else"), ACCEPT_LEAF);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER, keyAcc, ownerAcc);
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_transferOwnership_spendsBothNextTrees() public {
        (SHRINCS.RotationTarget memory t, SHRINCS.SigningKey memory key) = _makeRotationTarget("transfer-spends");
        SHRINCS.PublicKey memory next = _bundleOf(t);
        _assertTreesUnspent(next);
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(t, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(t, key, NEW_OWNER, NEW_OWNER_PK);
        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER, keyAcc, ownerAcc);
        assertEq(wallet.owner(), NEW_OWNER, "handed over");
        _assertTreesSpent(next);
    }

    function test_transferOwnership_revertsWhen_sameBundle() public {
        SHRINCS.RotationTarget memory same = _sameBundleTarget();
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(same, NEW_OWNER);
        // The "incoming" bundle IS the main key, so it signs the acceptance (at an unused leaf).
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(mainKey, mainCommitment, NEW_OWNER, SIGN_BASE + 5);
        bytes memory ownerAcc = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, mainCommitment);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, same, NEW_OWNER, keyAcc, ownerAcc);
    }

    /// @dev Regression (audit): a handover bundle may not reuse the dedicated ERC-1271 key's
    ///      stateless root — its trees are in the same lifetime registries as the main key's.
    function test_transferOwnership_revertsWhen_erc1271StatelessRootReused() public {
        (SHRINCS.SigningKey memory key, SHRINCS.PublicKey memory pk, bool ok) =
            SHRINCSTestSigner.keygen("transfer-erc1271-root", MAX_SIG);
        require(ok, "keygen");
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, erc1271Pk.pkSeed, erc1271Pk.hypertreeRoot);
        SHRINCS.RotationTarget memory t = SHRINCS.RotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(c),
            pkSeed: erc1271Pk.pkSeed,
            hypertreeRoot: erc1271Pk.hypertreeRoot
        });
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(t, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(t, key, NEW_OWNER, NEW_OWNER_PK);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(erc1271Pk)));
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER, keyAcc, ownerAcc);
    }

    function test_transferOwnership_revertsWhen_statelessTreeCarriedForward() public {
        (SHRINCS.RotationTarget memory t, SHRINCS.SigningKey memory key) =
            _freshStatefulSameStatelessTarget("transfer-carry-stateless");
        (SHRINCS.Signature memory ownerSig, SPHINCSPlusC.Signature memory recoverySig) = _currentOwnerSigs(t, NEW_OWNER);
        (SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) = _acceptance(t, key, NEW_OWNER, NEW_OWNER_PK);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER, keyAcc, ownerAcc);
    }
}
