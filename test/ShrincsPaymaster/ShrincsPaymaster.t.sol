// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.1.0/contracts/SHRINCS.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsTestSigner} from "@quip.network/hashsigs-solidity-0.1.0/test/helpers/ShrincsTestSigner.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsPaymasterHarness} from "../harness/ShrincsPaymasterHarness.sol";

/// @title ShrincsPaymaster Base Test
/// @dev Generates the global SHRINCS verifier key and every sponsorship signature in Solidity via
///      the dependency's test-only `ShrincsTestSigner`, so no external vectors are needed. Each
///      sponsorship signs the paymaster's `_userOpBindingHash` (read live via the harness) over a
///      `PackedUserOperation` built in-test.
contract ShrincsPaymasterTest is Test {
    // Fixed paymaster address + chain (kept stable so tests may hardcode values).
    address internal constant PAYMASTER = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    uint256 internal constant CHAIN_ID = 31337;
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint32 internal constant MAX_SIG = 8;
    // The fixed sponsored sender every sponsorship binds (`userOp.sender`).
    address internal constant SPONSOR_SENDER = address(0xA11CE);

    // `ActionContext.actionType` for sponsorship approvals (mirrors the contract's private tag).
    bytes32 internal constant ACTION_PAYMASTER_APPROVE = keccak256("quip.shrincs.action.paymasterApprove");

    // paymasterAndData layout offsets (mirror the contract constants).
    uint128 internal constant PM_VERIFICATION_GAS = 100_000;
    uint128 internal constant PM_POSTOP_GAS = 50_000;

    ShrincsPaymasterHarness internal paymaster;

    // The global verifier key (the sponsor's stateful signing key).
    ShrincsTypes.SigningKey internal verifierKey;
    ShrincsTypes.PublicKey internal verifierPk;
    bytes32 internal verifierCommitment;

    address internal OWNER;
    uint256 internal OWNER_PK;

    function setUp() public virtual {
        vm.chainId(CHAIN_ID);
        (OWNER, OWNER_PK) = makeAddrAndKey("owner");

        bool ok;
        (verifierKey, verifierPk, ok) = ShrincsTestSigner.keygen("shrincs-paymaster-test-verifier", MAX_SIG);
        assertTrue(ok, "verifier keygen");
        verifierCommitment = _toBytes32(verifierPk.publicKeyCommitment);

        ShrincsPaymasterHarness impl = new ShrincsPaymasterHarness();
        vm.etch(PAYMASTER, address(impl).code);
        paymaster = ShrincsPaymasterHarness(payable(PAYMASTER));

        paymaster.harness_setOwner(OWNER);
        paymaster.harness_install(verifierCommitment, MAX_SIG);
    }

    function test_setUp() public view virtual {
        assertEq(paymaster.owner(), OWNER);
        (bytes32 commitment, uint32 hashSuite, uint256 keyVersion, uint32 maxSignatures, uint32 statefulLeavesUsed) =
            paymaster.getShrincsVerifier();
        assertEq(commitment, verifierCommitment);
        assertEq(hashSuite, ShrincsTypes.HASH_SUITE_KECCAK_256);
        assertEq(keyVersion, 0);
        assertEq(maxSignatures, MAX_SIG);
        assertEq(statefulLeavesUsed, 0);
        assertFalse(paymaster.isStatefulLeafUsed(1));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    SIGNING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _toBytes32(bytes memory b) internal pure returns (bytes32 out) {
        require(b.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(b, 32))
        }
    }

    /// @dev The installed global verifier public key.
    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return verifierPk;
    }

    /// @dev A `StatefulSignature` whose only meaningful field is `authPath.length` (= the leaf
    ///      index), to drive the pre-verify leaf guards without a real signature.
    function _statefulSigWithLeaf(uint256 leaf) internal pure returns (ShrincsTypes.StatefulSignature memory sig) {
        sig.authPath = new bytes32[](leaf);
    }

    /// @dev Signs the paymaster's canonical sponsorship context over `bindingHash` at `leaf`.
    function _signSponsorship(bytes32 bindingHash, uint32 leaf)
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory sig)
    {
        (,, uint256 keyVersion,,) = paymaster.getShrincsVerifier();
        ShrincsTypes.ActionContext memory ctx = ShrincsTypes.ActionContext({
            domainSeparator: paymaster.exposed_domainSeparator(),
            nonce: 0,
            keyVersion: keyVersion,
            actionType: ACTION_PAYMASTER_APPROVE,
            payloadHash: bindingHash
        });
        bytes memory message = abi.encodePacked(SHRINCS.statefulActionMessageHash(verifierCommitment, ctx));
        bool ok;
        (sig, ok) = ShrincsTestSigner.signStatefulRawAtLeaf(verifierKey, leaf, message);
        require(ok, "sponsorship sign failed");
    }

    /// @dev A structurally valid leaf-1 signature (in budget, unused) that REACHES
    ///      `SHRINCS.verifyStateful` but is bound to a DIFFERENT userOp's binding hash (nonce 1),
    ///      so against the default nonce-0 op it fails verification (`InvalidSignature` branch).
    function _wrongContextStatefulSig() internal view returns (ShrincsTypes.StatefulSignature memory) {
        PackedUserOperation memory other = _userOp(SPONSOR_SENDER, _paymasterAndData(0, 0, ""));
        other.nonce = 1;
        return _signSponsorship(paymaster.exposed_userOpBindingHash(other), 1);
    }

    /// @dev Builds a fully signed sponsorship userOp for case `i`: leaf `i+1`, nonce `i+1`.
    ///      The binding hash covers only `paymasterAndData[:64]` (the prefix), so the op is first
    ///      built with an empty blob, signed, then rebuilt carrying the real (pk, sig) blob.
    function _sponsorUserOp(uint256 i) internal view returns (PackedUserOperation memory op, uint32 leaf) {
        leaf = uint32(i + 1);
        op = _userOp(SPONSOR_SENDER, _paymasterAndData(0, 0, ""));
        op.nonce = i + 1;
        ShrincsTypes.StatefulSignature memory sig =
            _signSponsorship(paymaster.exposed_userOpBindingHash(op), leaf);
        op.paymasterAndData = _paymasterAndData(0, 0, _blob(verifierPk, sig));
    }

    /// @dev A sponsorship signed over a NON-ZERO validity window, carried in the
    ///      `paymasterAndData` prefix exactly as signed. Returns the op, window bounds, and leaf.
    function _sponsorWithWindowUserOp()
        internal
        view
        returns (PackedUserOperation memory op, uint48 validUntil, uint48 validAfter, uint32 leaf)
    {
        leaf = 4;
        validUntil = uint48(1_900_000_000);
        validAfter = uint48(1_700_000_000);
        op = _userOp(SPONSOR_SENDER, _paymasterAndData(validUntil, validAfter, ""));
        op.nonce = 42;
        ShrincsTypes.StatefulSignature memory sig =
            _signSponsorship(paymaster.exposed_userOpBindingHash(op), leaf);
        op.paymasterAndData = _paymasterAndData(validUntil, validAfter, _blob(verifierPk, sig));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    USEROP HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ABI-encodes the `(PublicKey, StatefulSignature)` blob that lives at `paymasterAndData[64:]`.
    function _blob(ShrincsTypes.PublicKey memory pk, ShrincsTypes.StatefulSignature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(pk, sig);
    }

    /// @dev Assembles `paymasterAndData`: paymaster(20) | vGas(16) | postOpGas(16) | validUntil(6) |
    ///      validAfter(6) | blob.
    function _paymasterAndData(uint48 validUntil, uint48 validAfter, bytes memory blob)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(PAYMASTER, PM_VERIFICATION_GAS, PM_POSTOP_GAS, validUntil, validAfter, blob);
    }

    /// @dev Convenience: a `paymasterAndData` carrying a given pk+sig with zero validity window.
    function _pmData(ShrincsTypes.PublicKey memory pk, ShrincsTypes.StatefulSignature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        return _paymasterAndData(0, 0, _blob(pk, sig));
    }

    /// @dev Minimal `PackedUserOperation` for the given sender + paymasterAndData.
    function _userOp(address sender, bytes memory pmData) internal pure returns (PackedUserOperation memory op) {
        op.sender = sender;
        op.nonce = 0;
        op.initCode = "";
        op.callData = "";
        op.accountGasLimits = bytes32((uint256(100_000) << 128) | uint256(100_000));
        op.preVerificationGas = 21_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(10 gwei));
        op.paymasterAndData = pmData;
        op.signature = "";
    }

    /// @dev Calls `validatePaymasterUserOp` impersonating the EntryPoint.
    function _validate(PackedUserOperation memory op) internal returns (bytes memory context, uint256 validationData) {
        vm.prank(ENTRY_POINT);
        return paymaster.validatePaymasterUserOp(op, bytes32(0), 1 ether);
    }
}
