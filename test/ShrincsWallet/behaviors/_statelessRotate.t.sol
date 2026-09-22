// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
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
    SPHINCSPlusC.Signature internal validSig;
    SHRINCS.RotationContext internal ctx;

    function setUp() public override {
        super.setUp();
        (target,) = _makeRotationTarget("stateless-rotate-target");
        validSig = _signFullRotation(target, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        ctx = _rotationContext(Codec.ROTATION_DOMAIN_RECOVER_WALLET);
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertEq(target.publicKeyCommitment.length, 32, "replacement bundle shaped");
        assertTrue(
            _toBytes32(target.publicKeyCommitment) != wallet.getShrincsPublicKeyCommitment(),
            "replacement differs from the installed key"
        );
    }

    function _rotate(SHRINCS.RotationTarget memory nextKey, SPHINCSPlusC.Signature memory sig)
        internal
        view
        returns (bytes32)
    {
        return wallet.exposed_statelessRotate(
            wallet.getShrincsPublicKeyCommitment(), _mainPk(), ctx, sig, nextKey
        );
    }

    function test_exposed_statelessRotate_returnsComputedCommitmentOnSuccess() public view {
        assertEq(
            _rotate(target, validSig),
            _toBytes32(target.publicKeyCommitment),
            "computed next commitment returned"
        );
    }

    function test_exposed_statelessRotate_returnsZeroWhen_statefulKeyWrongLength() public view {
        SHRINCS.RotationTarget memory bad = target;
        bad.statefulPublicKey = hex"01";
        assertEq(_rotate(bad, validSig), bytes32(0), "truncated stateful key rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_commitmentWrongLength() public view {
        SHRINCS.RotationTarget memory bad = target;
        bad.publicKeyCommitment = new bytes(31);
        assertEq(_rotate(bad, validSig), bytes32(0), "non-32-byte commitment rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_pkSeedWrongLength() public view {
        SHRINCS.RotationTarget memory bad = target;
        bad.pkSeed = new bytes(33);
        assertEq(_rotate(bad, validSig), bytes32(0), "non-32-byte pkSeed rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_hypertreeRootWrongLength() public view {
        SHRINCS.RotationTarget memory bad = target;
        bad.hypertreeRoot = new bytes(0);
        assertEq(_rotate(bad, validSig), bytes32(0), "empty hypertree root rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_zeroMaxSignatures() public view {
        SHRINCS.RotationTarget memory bad = target;
        bytes memory spk = bad.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0;
        bad.statefulPublicKey = spk;
        assertEq(_rotate(bad, validSig), bytes32(0), "zero-budget replacement key rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_declaredCommitmentMismatch() public view {
        SHRINCS.RotationTarget memory bad = target;
        bad.publicKeyCommitment = abi.encodePacked(keccak256("wrong-declared-commitment"));
        assertEq(_rotate(bad, validSig), bytes32(0), "declared != recomputed rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_invalidRecoverySignature() public view {
        SPHINCSPlusC.Signature memory empty;
        assertEq(_rotate(target, empty), bytes32(0), "unverifiable recovery signature rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signatureBoundToOtherTarget() public {
        // A signature valid for a DIFFERENT replacement bundle must not authorize this one.
        (SHRINCS.RotationTarget memory other,) = _makeRotationTarget("stateless-rotate-other");
        SPHINCSPlusC.Signature memory otherSig =
            _signFullRotation(other, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        assertEq(_rotate(target, otherSig), bytes32(0), "cross-target signature rejected");
    }

    function test_exposed_statelessRotate_returnsZeroWhen_signedUnderOtherRotationDomain() public {
        // A transfer-ownership-domain signature must not authorize a recover-wallet rotation.
        SPHINCSPlusC.Signature memory crossSig =
            _signFullRotation(target, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        assertEq(_rotate(target, crossSig), bytes32(0), "cross-domain signature rejected");
    }

    /// @dev Declared-vs-recomputed equality is the authorization semantics: the signature binds
    ///      the DECLARED bytes while the wallet installs the RECOMPUTED value. A tampered
    ///      declaration must fail even when the recovery signature is freshly made over it —
    ///      otherwise a signed lie would install an unverified bundle.
    function test_exposed_statelessRotate_returnsZeroWhen_tamperedCommitmentSigned() public {
        SHRINCS.RotationTarget memory bad = target;
        bad.publicKeyCommitment = abi.encodePacked(keccak256("tampered-declared-commitment"));
        SPHINCSPlusC.Signature memory sig =
            _signFullRotation(bad, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        assertEq(_rotate(bad, sig), bytes32(0), "signed tampered declaration rejected");
    }
}
