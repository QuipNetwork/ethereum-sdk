// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev A contract recipient: accepts exactly the digests it was told to.
contract AcceptingRecipient {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    mapping(bytes32 => bool) public accepted;

    function accept(bytes32 digest) external {
        accepted[digest] = true;
    }

    function isValidSignature(bytes32 digest, bytes calldata) external view returns (bytes4) {
        return accepted[digest] ? MAGIC : bytes4(0);
    }
}

/// @dev Behavior tests for the internal `_verifyOwnershipAcceptance` (via the harness): the
///      incoming party's hybrid proof of control in a `transferOwnership`. Succeeds — returning the
///      acceptance leaf — only when BOTH halves verify for exactly `(newOwner, nextCommitment)`:
///      the classical half (`newOwner`'s ECDSA, or ERC-1271 for a contract) over the wallet's
///      `QuipSignedHash` target of the handover payload, and the stateful half from the incoming
///      bundle itself, bound to ITS commitment at nonce 0 / epoch 0 under `ACTION_TRANSFER_OWNERSHIP`.
///      Every classical failure is `InvalidOwnerAcceptance`, every PQ failure `InvalidKeyAcceptance`;
///      the classical half is checked first. View-only: nothing is consumed or recorded.
contract ShrincsWallet__verifyOwnershipAcceptance is ShrincsWalletTest {
    address internal NEW_OWNER;
    uint256 internal NEW_OWNER_PK;
    uint32 internal constant ACCEPT_LEAF = 1;

    // The incoming bundle (the recipient's) and its signing key.
    SHRINCS.RotationTarget internal nextKey;
    SHRINCS.SigningKey internal nextSigningKey;
    bytes32 internal nextCommitment;

    function setUp() public virtual override {
        super.setUp();
        (NEW_OWNER, NEW_OWNER_PK) = makeAddrAndKey("acceptance-recipient");
        (nextKey, nextSigningKey) = _makeRotationTarget("verify-ownership-acceptance-next-key");
        nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
    }

    function test_setUp() public view virtual override {
        super.test_setUp();
        assertEq(vm.addr(NEW_OWNER_PK), NEW_OWNER, "recipient key pair");
        assertTrue(NEW_OWNER != OWNER, "recipient is a distinct party");
        assertTrue(nextCommitment != mainCommitment, "incoming bundle is not the installed one");
        assertEq(
            nextCommitment,
            SHRINCS.publicKeyCommitmentFromParts(nextKey.statefulPublicKey, nextKey.pkSeed, nextKey.hypertreeRoot),
            "commitment recomputes"
        );
        _assertTreesUnspent(_bundleOf(nextKey));
    }

    /*──────────────────── helpers ────────────────────*/

    function _keyAcc() internal view returns (SHRINCS.Signature memory) {
        return _signKeyAcceptance(nextSigningKey, nextCommitment, NEW_OWNER, ACCEPT_LEAF);
    }

    function _ownerAcc() internal view returns (bytes memory) {
        return _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, nextCommitment);
    }

    function _verify(SHRINCS.Signature memory keyAcc, bytes memory ownerAcc) internal view returns (uint32) {
        return wallet.exposed_verifyOwnershipAcceptance(nextKey, nextCommitment, NEW_OWNER, MAX_SIG, keyAcc, ownerAcc);
    }

    /// @dev Snapshot of everything the check must leave untouched.
    function _stateFingerprint() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                wallet.actionNonce(),
                wallet.keyVersion(),
                wallet.statefulLeavesUsed(),
                wallet.statefulLeafBitmapWord(0),
                wallet.getShrincsPublicKeyCommitment(),
                wallet.owner()
            )
        );
    }

    /*──────────────────── happy paths ────────────────────*/

    function test_verifyOwnershipAcceptance_returnsAcceptanceLeaf() public view {
        assertEq(_verify(_keyAcc(), _ownerAcc()), ACCEPT_LEAF);
    }

    function test_verifyOwnershipAcceptance_acceptsAnyLeafInBudget() public view {
        SHRINCS.Signature memory atBudget = _signKeyAcceptance(nextSigningKey, nextCommitment, NEW_OWNER, MAX_SIG);
        assertEq(_verify(atBudget, _ownerAcc()), MAX_SIG);
        SHRINCS.Signature memory mid = _signKeyAcceptance(nextSigningKey, nextCommitment, NEW_OWNER, SIGN_BASE);
        assertEq(_verify(mid, _ownerAcc()), SIGN_BASE);
    }

    function test_verifyOwnershipAcceptance_isPure_consumesNothing() public {
        bytes32 before = _stateFingerprint();
        _verify(_keyAcc(), _ownerAcc());
        assertEq(_stateFingerprint(), before, "no leaf, nonce, epoch or owner change");
        assertFalse(wallet.isStatefulLeafUsed(ACCEPT_LEAF), "acceptance leaf is the caller's to record");
        _assertTreesUnspent(_bundleOf(nextKey));
    }

    /// @dev The acceptance is independent of the wallet's live state: signed at nonce 0 / epoch 0,
    ///      it still verifies after the current owner consumes signatures.
    function test_verifyOwnershipAcceptance_independentOfLiveNonce() public {
        SHRINCS.Signature memory keyAcc = _keyAcc();
        bytes memory ownerAcc = _ownerAcc();
        bytes32 executeHash = Codec.executePayloadHash(address(0xBEEF), 0, keccak256(""), 0);
        SHRINCS.Signature memory executeSig = _signStatefulAction(Codec.ACTION_EXECUTE, executeHash, 2);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), executeSig, address(0xBEEF), 0, "", 0);
        assertEq(wallet.actionNonce(), 1);
        assertEq(_verify(keyAcc, ownerAcc), ACCEPT_LEAF);
    }

    function test_verifyOwnershipAcceptance_contractRecipient_viaErc1271() public {
        AcceptingRecipient recipient = new AcceptingRecipient();
        bytes32 payloadHash = Codec.transferOwnershipPayloadHash(address(recipient), nextCommitment);
        recipient.accept(wallet.quipSignedHashEcdsaTarget(payloadHash));
        SHRINCS.Signature memory keyAcc =
            _signKeyAcceptance(nextSigningKey, nextCommitment, address(recipient), ACCEPT_LEAF);
        assertEq(
            wallet.exposed_verifyOwnershipAcceptance(
                nextKey, nextCommitment, address(recipient), MAX_SIG, keyAcc, ""
            ),
            ACCEPT_LEAF
        );
    }

    /*──────────────────── classical half → InvalidOwnerAcceptance ────────────────────*/

    function test_verifyOwnershipAcceptance_revertsWhen_ownerAcceptanceEmpty() public {
        SHRINCS.Signature memory keyAcc = _keyAcc();
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(keyAcc, "");
    }

    function test_verifyOwnershipAcceptance_revertsWhen_ownerAcceptanceMalformed() public {
        SHRINCS.Signature memory keyAcc = _keyAcc();
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(keyAcc, hex"deadbeef");
    }

    function test_verifyOwnershipAcceptance_revertsWhen_ownerAcceptanceByOtherSigner() public {
        SHRINCS.Signature memory keyAcc = _keyAcc();
        bytes memory byCurrentOwner = _signOwnerAcceptance(OWNER_PK, NEW_OWNER, nextCommitment);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(keyAcc, byCurrentOwner);
    }

    /// @dev The audit scenario: `newOwner` is a typo of the intended recipient's address.
    function test_verifyOwnershipAcceptance_revertsWhen_newOwnerMistyped() public {
        address typo = makeAddr("acceptance-recipient-typo");
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(nextSigningKey, nextCommitment, typo, ACCEPT_LEAF);
        bytes memory ownerAcc = _ownerAcc(); // the real recipient signed for THEIR address
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.exposed_verifyOwnershipAcceptance(nextKey, nextCommitment, typo, MAX_SIG, keyAcc, ownerAcc);
    }

    function test_verifyOwnershipAcceptance_revertsWhen_ownerAcceptanceForOtherCommitment() public {
        (SHRINCS.RotationTarget memory other,) = _makeRotationTarget("verify-ownership-acceptance-other");
        SHRINCS.Signature memory keyAcc = _keyAcc();
        bytes memory forOther = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, _toBytes32(other.publicKeyCommitment));
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(keyAcc, forOther);
    }

    /// @dev The wallet's other ECDSA surface (userOp co-signature target) over the same payload
    ///      hash is not an acceptance.
    function test_verifyOwnershipAcceptance_revertsWhen_ownerAcceptanceUnderUserOpTypehash() public {
        SHRINCS.Signature memory keyAcc = _keyAcc();
        bytes32 payloadHash = Codec.transferOwnershipPayloadHash(NEW_OWNER, nextCommitment);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NEW_OWNER_PK, wallet.quipUserOpHashEcdsaTarget(payloadHash));
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(keyAcc, abi.encodePacked(r, s, v));
    }

    /// @dev A raw (non-typed-data) signature over the payload hash is not an acceptance either.
    function test_verifyOwnershipAcceptance_revertsWhen_ownerAcceptanceOverRawPayloadHash() public {
        SHRINCS.Signature memory keyAcc = _keyAcc();
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(NEW_OWNER_PK, Codec.transferOwnershipPayloadHash(NEW_OWNER, nextCommitment));
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(keyAcc, abi.encodePacked(r, s, v));
    }

    function test_verifyOwnershipAcceptance_contractRecipient_revertsWhen_notAccepting() public {
        AcceptingRecipient recipient = new AcceptingRecipient();
        SHRINCS.Signature memory keyAcc =
            _signKeyAcceptance(nextSigningKey, nextCommitment, address(recipient), ACCEPT_LEAF);
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        wallet.exposed_verifyOwnershipAcceptance(nextKey, nextCommitment, address(recipient), MAX_SIG, keyAcc, "");
    }

    /// @dev Check order: the cheap classical half is rejected before the PQ verifier is reached.
    function test_verifyOwnershipAcceptance_checksClassicalHalfFirst() public {
        SHRINCS.Signature memory empty;
        vm.expectRevert(IShrincsWallet.InvalidOwnerAcceptance.selector);
        _verify(empty, "");
    }

    /*──────────────────── PQ half → InvalidKeyAcceptance ────────────────────*/

    function test_verifyOwnershipAcceptance_revertsWhen_keyAcceptanceEmpty() public {
        SHRINCS.Signature memory empty;
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(empty, ownerAcc);
    }

    function test_verifyOwnershipAcceptance_revertsWhen_leafOverBudget() public {
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(_statefulSigWithLeaf(MAX_SIG + 1), ownerAcc);
    }

    /// @dev The budget argument is what gates: a genuine signature at leaf `MAX_SIG` is rejected
    ///      when the caller declares a smaller budget for the incoming key.
    function test_verifyOwnershipAcceptance_revertsWhen_leafExceedsDeclaredBudget() public {
        SHRINCS.Signature memory atBudget = _signKeyAcceptance(nextSigningKey, nextCommitment, NEW_OWNER, MAX_SIG);
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.exposed_verifyOwnershipAcceptance(nextKey, nextCommitment, NEW_OWNER, MAX_SIG - 1, atBudget, ownerAcc);
    }

    function test_verifyOwnershipAcceptance_revertsWhen_signedByCurrentKey() public {
        SHRINCS.Signature memory byCurrent = _signKeyAcceptance(mainKey, nextCommitment, NEW_OWNER, SIGN_BASE + 3);
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(byCurrent, ownerAcc);
    }

    /// @dev The stateful half binds the INCOMING commitment, never the installed one.
    function test_verifyOwnershipAcceptance_revertsWhen_signedUnderInstalledCommitment() public {
        SHRINCS.Signature memory underInstalled =
            _signKeyAcceptance(nextSigningKey, mainCommitment, NEW_OWNER, ACCEPT_LEAF);
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(underInstalled, ownerAcc);
    }

    /// @dev `nextCommitment` must be the bundle's own: a mismatched expected commitment fails the
    ///      verifier's bundle check (and the classical half, which binds it too, is signed for it).
    function test_verifyOwnershipAcceptance_revertsWhen_commitmentNotTheBundles() public {
        (SHRINCS.RotationTarget memory other,) = _makeRotationTarget("verify-ownership-acceptance-other");
        bytes32 otherCommitment = _toBytes32(other.publicKeyCommitment);
        SHRINCS.Signature memory keyAcc = _signKeyAcceptance(nextSigningKey, otherCommitment, NEW_OWNER, ACCEPT_LEAF);
        bytes memory ownerAcc = _signOwnerAcceptance(NEW_OWNER_PK, NEW_OWNER, otherCommitment);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        wallet.exposed_verifyOwnershipAcceptance(nextKey, otherCommitment, NEW_OWNER, MAX_SIG, keyAcc, ownerAcc);
    }

    function test_verifyOwnershipAcceptance_revertsWhen_signedForOtherOwner() public {
        SHRINCS.Signature memory forOther =
            _signKeyAcceptance(nextSigningKey, nextCommitment, makeAddr("someone-else"), ACCEPT_LEAF);
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(forOther, ownerAcc);
    }

    function test_verifyOwnershipAcceptance_revertsWhen_signedUnderOtherAction() public {
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            wallet.exposed_shrincsDomainSeparator(),
            0,
            0,
            Codec.ACTION_EXECUTE,
            Codec.transferOwnershipPayloadHash(NEW_OWNER, nextCommitment)
        );
        SHRINCS.Signature memory otherAction = _signStatefulActionWith(nextSigningKey, nextCommitment, ctx, ACCEPT_LEAF);
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(otherAction, ownerAcc);
    }

    /// @dev Pins the nonce 0 / epoch 0 context: a signature under the LIVE context (after the
    ///      wallet moves off nonce 0) is not an acceptance.
    function test_verifyOwnershipAcceptance_revertsWhen_signedUnderLiveContext() public {
        bytes32 executeHash = Codec.executePayloadHash(address(0xBEEF), 0, keccak256(""), 0);
        SHRINCS.Signature memory executeSig = _signStatefulAction(Codec.ACTION_EXECUTE, executeHash, 2);
        vm.prank(OWNER);
        wallet.execute(_mainPk(), executeSig, address(0xBEEF), 0, "", 0);
        assertEq(wallet.actionNonce(), 1);

        SHRINCS.Signature memory live = _signStatefulActionWith(
            nextSigningKey,
            nextCommitment,
            _actionContext(Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(NEW_OWNER, nextCommitment)),
            ACCEPT_LEAF
        );
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(live, ownerAcc);
    }

    /// @dev The verifier's revert-as-rejection channel maps to `InvalidKeyAcceptance`, never a
    ///      bare revert: garbage signature internals are just an invalid acceptance.
    function test_verifyOwnershipAcceptance_revertsWhen_signatureTampered() public {
        SHRINCS.Signature memory tampered = _keyAcc();
        tampered.chains[0] = ~tampered.chains[0];
        bytes memory ownerAcc = _ownerAcc();
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(tampered, ownerAcc);

        SHRINCS.Signature memory garbage = _keyAcc();
        garbage.chains = new bytes32[](1);
        vm.expectRevert(IShrincsWallet.InvalidKeyAcceptance.selector);
        _verify(garbage, ownerAcc);
    }
}
