// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_statelessRotate` (via `exposed_statelessRotate`), the validator behind
///      `recoverWallet`/`transferOwnership`: fixed-width shape checks on the replacement bundle,
///      zero-budget rejection, declared-vs-computed commitment recompute, and the stateless
///      recovery-signature verify over the canonical full-rotation message. It rejects by
///      returning `bytes32(0)` (the callers surface that as `InvalidSignature`), so the cases
///      here assert the zero return rather than reverts.
contract ShrincsWallet__statelessRotate is ShrincsWalletTest {
    SHRINCS.RotationTarget internal target;
    bytes internal validSig;
    SHRINCS.RotationContext internal ctx;

    function setUp() public override {
        super.setUp();
        (target, ) = _makeRotationTarget("stateless-rotate-target");
        validSig = _signFullRotation(
            target,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        ctx = _rotationContext(Codec.ROTATION_DOMAIN_RECOVER_WALLET);
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertEq(
            target.publicKeyCommitment.length,
            32,
            "replacement bundle shaped"
        );
        assertTrue(
            _toBytes32(target.publicKeyCommitment) !=
                wallet.getShrincsPublicKeyCommitment(),
            "replacement differs from the installed key"
        );
    }

    function _rotate(
        SHRINCS.RotationTarget memory nextKey,
        bytes memory sig
    ) internal view returns (bytes32) {
        return
            wallet.exposed_statelessRotate(
                wallet.getShrincsPublicKeyCommitment(),
                _mainPk(),
                ctx,
                sig,
                nextKey
            );
    }

    function test_exposed_statelessRotate_returnsComputedCommitmentOnSuccess()
        public
        view
    {
        assertEq(
            _rotate(target, validSig),
            _toBytes32(target.publicKeyCommitment),
            "computed next commitment returned"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_statefulKeyWrongLength()
        public
        view
    {
        SHRINCS.RotationTarget memory bad = target;
        bad.statefulPublicKey = hex"01";
        assertEq(
            _rotate(bad, validSig),
            bytes32(0),
            "truncated stateful key rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_commitmentWrongLength()
        public
        view
    {
        SHRINCS.RotationTarget memory bad = target;
        bad.publicKeyCommitment = new bytes(31);
        assertEq(
            _rotate(bad, validSig),
            bytes32(0),
            "non-32-byte commitment rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_pkSeedWrongLength()
        public
        view
    {
        SHRINCS.RotationTarget memory bad = target;
        bad.pkSeed = new bytes(33);
        assertEq(
            _rotate(bad, validSig),
            bytes32(0),
            "non-32-byte pkSeed rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_hypertreeRootWrongLength()
        public
        view
    {
        SHRINCS.RotationTarget memory bad = target;
        bad.hypertreeRoot = new bytes(0);
        assertEq(
            _rotate(bad, validSig),
            bytes32(0),
            "empty hypertree root rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_zeroMaxSignatures()
        public
        view
    {
        SHRINCS.RotationTarget memory bad = target;
        bytes memory spk = bad.statefulPublicKey;
        _zeroMaxSignatures(spk);
        bad.statefulPublicKey = spk;
        assertEq(
            _rotate(bad, validSig),
            bytes32(0),
            "zero-budget replacement key rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_declaredCommitmentMismatch()
        public
        view
    {
        SHRINCS.RotationTarget memory bad = target;
        bad.publicKeyCommitment = abi.encodePacked(
            keccak256("wrong-declared-commitment")
        );
        assertEq(
            _rotate(bad, validSig),
            bytes32(0),
            "declared != recomputed rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_invalidRecoverySignature()
        public
        view
    {
        bytes memory empty;
        assertEq(
            _rotate(target, empty),
            bytes32(0),
            "unverifiable recovery signature rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signatureBoundToOtherTarget()
        public
    {
        // A signature valid for a DIFFERENT replacement bundle must not authorize this one.
        (SHRINCS.RotationTarget memory other, ) = _makeRotationTarget(
            "stateless-rotate-other"
        );
        bytes memory otherSig = _signFullRotation(
            other,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        assertEq(
            _rotate(target, otherSig),
            bytes32(0),
            "cross-target signature rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signedUnderOtherRotationDomain()
        public
    {
        // A transfer-ownership-domain signature must not authorize a recover-wallet rotation.
        bytes memory crossSig = _signFullRotation(
            target,
            Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP
        );
        assertEq(
            _rotate(target, crossSig),
            bytes32(0),
            "cross-domain signature rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signedMismatchedCommitment()
        public
    {
        SHRINCS.RotationTarget memory mismatchedTarget = target;
        mismatchedTarget.publicKeyCommitment = abi.encodePacked(
            keccak256("tampered-declared-commitment")
        );
        bytes memory recoverySignature = _signFullRotation(
            mismatchedTarget,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        assertEq(
            _rotate(mismatchedTarget, recoverySignature),
            bytes32(0),
            "signed tampered declaration rejected"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signedShortSeedWithMatchingCommitment()
        public
    {
        SHRINCS.RotationTarget memory shortSeedTarget = target;
        shortSeedTarget.pkSeed = new bytes(31);
        shortSeedTarget.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(
                shortSeedTarget.statefulPublicKey,
                shortSeedTarget.pkSeed,
                shortSeedTarget.hypertreeRoot
            )
        );
        bytes memory recoverySignature = _signFullRotation(
            shortSeedTarget,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        assertEq(
            _rotate(shortSeedTarget, recoverySignature),
            bytes32(0),
            "off-width pkSeed rejected despite consistency"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signedLongRootWithMatchingCommitment()
        public
    {
        SHRINCS.RotationTarget memory longRootTarget = target;
        longRootTarget.hypertreeRoot = new bytes(33);
        longRootTarget.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(
                longRootTarget.statefulPublicKey,
                longRootTarget.pkSeed,
                longRootTarget.hypertreeRoot
            )
        );
        bytes memory recoverySignature = _signFullRotation(
            longRootTarget,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        assertEq(
            _rotate(longRootTarget, recoverySignature),
            bytes32(0),
            "off-width root rejected despite consistency"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signedZeroBudgetWithMatchingCommitment()
        public
    {
        SHRINCS.RotationTarget memory zeroBudgetTarget = target;
        bytes memory statefulPublicKey = zeroBudgetTarget.statefulPublicKey;
        _zeroMaxSignatures(statefulPublicKey);
        zeroBudgetTarget.statefulPublicKey = statefulPublicKey;
        zeroBudgetTarget.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(
                statefulPublicKey,
                zeroBudgetTarget.pkSeed,
                zeroBudgetTarget.hypertreeRoot
            )
        );
        bytes memory recoverySignature = _signFullRotation(
            zeroBudgetTarget,
            Codec.ROTATION_DOMAIN_RECOVER_WALLET
        );
        assertEq(
            _rotate(zeroBudgetTarget, recoverySignature),
            bytes32(0),
            "zero-budget replacement rejected despite consistency"
        );
    }

    /* ───────────────── fixed-layout recovery signature (PQ section) ───────────────── */

    function test_exposed_statelessRotate_recoverySignatureHasLayoutLength() public view {
        assertEq(validSig.length, StatelessLayout.PQ_LEN, "PQ section width");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_recoverySignatureTruncated() public view {
        bytes memory sig = validSig;
        assembly {
            mstore(sig, sub(mload(sig), 1))
        }
        assertEq(_rotate(target, sig), bytes32(0), "one byte short rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_recoverySignatureExtended() public view {
        assertEq(_rotate(target, abi.encodePacked(validSig, bytes1(0))), bytes32(0), "one byte long rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_recoverySignatureBitFlipped() public view {
        bytes memory sig = validSig;
        sig[0] ^= 0x01; // FORS randomizer
        assertEq(_rotate(target, sig), bytes32(0), "flipped first byte rejected");
        sig[0] ^= 0x01;
        sig[sig.length - 1] ^= 0x01; // last hypertree auth-path byte
        assertEq(_rotate(target, sig), bytes32(0), "flipped last byte rejected");
    }

    /// @dev The pre-0.4.0 ABI encoding of a signature is not a valid PQ section.
    function test_exposed_statelessRotate_returnsZeroWhen_recoverySignatureAbiEncoded() public view {
        assertEq(_rotate(target, abi.encode(validSig)), bytes32(0), "ABI-wrapped signature rejected");
    }

    /* ───────────────────── current public key (PK section) ───────────────────── */

    function _rotateWithCurrent(SHRINCS.PublicKey memory current) internal view returns (bytes32) {
        return wallet.exposed_statelessRotate(
            wallet.getShrincsPublicKeyCommitment(), current, ctx, validSig, target
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_currentStatefulKeyWrongLength() public view {
        SHRINCS.PublicKey memory bad = _mainPk();
        bad.statefulPublicKey = bytes.concat(bad.statefulPublicKey, hex"00");
        assertEq(_rotateWithCurrent(bad), bytes32(0), "mis-sized current statefulPublicKey rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_currentPkSeedWrongLength() public view {
        SHRINCS.PublicKey memory bad = _mainPk();
        bad.pkSeed = new bytes(31);
        assertEq(_rotateWithCurrent(bad), bytes32(0), "mis-sized current pkSeed rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_currentHypertreeRootWrongLength() public view {
        SHRINCS.PublicKey memory bad = _mainPk();
        bad.hypertreeRoot = new bytes(33);
        assertEq(_rotateWithCurrent(bad), bytes32(0), "mis-sized current hypertreeRoot rejected");
    }

    /// @dev Field widths that still sum to `PK_LEN`: the verifier's total-length check alone would
    ///      pass, so the wallet's per-field check is what rejects.
    function test_exposed_statelessRotate_returnsZeroWhen_currentFieldBoundaryShifted() public view {
        SHRINCS.PublicKey memory bad = _mainPk();
        bytes memory seed = bad.pkSeed;
        bytes memory root = bad.hypertreeRoot;
        bad.pkSeed = bytes.concat(seed, bytes1(root[0]));
        bytes memory shortRoot = new bytes(31);
        for (uint256 i; i < 31; ++i) {
            shortRoot[i] = root[i + 1];
        }
        bad.hypertreeRoot = shortRoot;
        assertEq(_rotateWithCurrent(bad), bytes32(0), "shifted pkSeed/hypertreeRoot boundary rejected");
    }

    /// @dev A well-formed bundle that is not the installed key: its commitment is not the
    ///      wallet's, so the verifier rejects.
    function test_exposed_statelessRotate_returnsZeroWhen_currentKeyIsOtherBundle() public view {
        assertEq(_rotateWithCurrent(erc1271Pk), bytes32(0), "foreign bundle rejected");
    }
}
