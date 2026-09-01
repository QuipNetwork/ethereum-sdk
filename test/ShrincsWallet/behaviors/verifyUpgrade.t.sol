// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the `verifyUpgrade` PROBE (the frozen `IWallet` seam): a throwaway
///      bundle must verify under BOTH halves via the pinned verifier over the recomputed
///      `probeDigest(newImplementation)`, and nothing about the wallet's own state may matter.
///      Accepts the bare 3-field vector (seam convention) AND the full auth blob the DEPLOYED
///      SHRINCS implementation forwards (canonical head word[0] == 0xc0).
contract ShrincsWallet_verifyUpgrade is ShrincsWalletTest {
    SHRINCS.SigningKey internal probeKey;
    SHRINCS.PublicKey internal probePk;

    /// @dev The probed upgrade target; the signed digest binds it.
    address internal constant TARGET = address(0xBEEF);
    bytes32 internal targetDigest;

    function setUp() public override {
        super.setUp();
        bool ok;
        (probeKey, probePk, ok) = SHRINCSTestSigner.keygen("probe-upgrade-throwaway", MAX_SIG);
        assertTrue(ok, "probe keygen");
        targetDigest = Codec.probeDigest(TARGET);
    }

    /// @dev Raw-digest stateful signature from the throwaway key (no wallet context).
    function _statefulProbeSig(bytes32 digest) internal view returns (SHRINCS.Signature memory sig) {
        bytes memory message =
            abi.encodePacked(SHRINCS.statefulRawMessageHash(_commitment32(probePk), digest));
        bool ok;
        (sig, ok) = SHRINCSTestSigner.signStatefulRawAtLeaf(probeKey, SIGN_BASE + 1, message);
        require(ok, "probe stateful sign failed");
    }

    /// @dev Raw-digest stateless signature from the throwaway key (no wallet context).
    function _statelessProbeSig(bytes32 digest) internal returns (SPHINCSPlusC.Signature memory) {
        bytes memory message =
            abi.encodePacked(SHRINCS.statelessRawMessageHash(_commitment32(probePk), digest));
        return _signStatelessRaw(probeKey, probePk, message);
    }

    /// @dev The bare 3-field probe vector; the digest is NOT carried — the wallet recomputes it.
    function _vector(bytes32 digest) internal returns (bytes memory) {
        return abi.encode(probePk, _statefulProbeSig(digest), _statelessProbeSig(digest));
    }

    function test_verifyUpgrade_succeeds() public {
        wallet.verifyUpgrade(TARGET, _vector(targetDigest));
    }

    /// @dev Context-free pin: the probe must succeed on a BARE implementation (no proxy, no
    ///      initialized storage) — it may depend on nothing but its calldata.
    function test_verifyUpgrade_succeedsOnUninitializedImplementation() public {
        ShrincsWalletHarness bare =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        bare.verifyUpgrade(TARGET, _vector(targetDigest));
    }

    /// @dev Deployed-implementation compat: the LIVE SHRINCS implementation forwards its ENTIRE
    ///      auth blob (head word[0] == 0xc0); the probe vector is extracted from field[5].
    function test_verifyUpgrade_succeedsWithFullAuthBlob() public {
        bytes memory blob = abi.encode(
            probePk, _statefulProbeSig(targetDigest), false, bytes(""), uint256(0), _vector(targetDigest)
        );
        assertEq(uint256(bytes32(blob)), 0xc0, "canonical 6-field blob head");
        wallet.verifyUpgrade(TARGET, blob);
    }

    /// @dev The recomputed digest binds `newImplementation`: a vector signed for TARGET must
    ///      fail when probed against a different implementation address.
    function test_verifyUpgrade_revertsWhen_wrongTarget() public {
        bytes memory vector = _vector(targetDigest);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(address(0xCAFE), vector);
    }

    function test_verifyUpgrade_revertsWhen_statefulSigInvalid() public {
        bytes memory vector = abi.encode(
            probePk,
            _statefulProbeSig(keccak256("some other digest")),
            _statelessProbeSig(targetDigest)
        );
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(TARGET, vector);
    }

    function test_verifyUpgrade_revertsWhen_statelessSigInvalid() public {
        bytes memory vector = abi.encode(
            probePk,
            _statefulProbeSig(targetDigest),
            _statelessProbeSig(keccak256("some other digest"))
        );
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(TARGET, vector);
    }

    /// @dev Signatures from the throwaway key presented under a DIFFERENT bundle: the derived
    ///      commitment changes, so verification rejects.
    function test_verifyUpgrade_revertsWhen_bundleMismatchesSignatures() public {
        bytes memory vector =
            abi.encode(_mainPk(), _statefulProbeSig(targetDigest), _statelessProbeSig(targetDigest));
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.verifyUpgrade(TARGET, vector);
    }

    function test_verifyUpgrade_revertsWhen_malformedPayload() public {
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x60, 0x40));
        wallet.verifyUpgrade(TARGET, new bytes(0x40));
    }
}
