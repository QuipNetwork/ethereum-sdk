// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsPaymasterHarness} from "../harness/ShrincsPaymasterHarness.sol";

/// @title ShrincsPaymaster Base Test
/// @dev Places the harness at the fixed paymaster address (`vm.etch` + `vm.chainId`) the Rust
///      generator bound the vectors to, so `_domainSeparator()` reproduces the baked
///      `domainSeparator`. Loads the dedicated SHRINCS verifier key + sponsorship signatures from
///      `shrincs_paymaster_sphincs_256s_keccak.json`. Each sponsorship signs the paymaster's
///      `_userOpBindingHash` over a fixed userOp (nonce varies per case); the test rebuilds the
///      identical `PackedUserOperation` from the vector's pinned `userOp` fields.
contract ShrincsPaymasterTest is Test {
    string internal constant VECTORS =
        "test/test_vectors/shrincs_paymaster_sphincs_256s_keccak.json";

    // Fixed paymaster address + chain so the SHRINCS domain separator is reproducible for vectors.
    address internal constant PAYMASTER =
        0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    uint256 internal constant CHAIN_ID = 31337;
    address internal constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    uint32 internal constant MAX_SIG = 8;
    // The fixed sponsored sender the vectors bind (vector `userOp.sender`).
    address internal constant SPONSOR_SENDER = address(0xA11CE);

    // paymasterAndData layout offsets (mirror the contract constants).
    uint128 internal constant PM_VERIFICATION_GAS = 100_000;
    uint128 internal constant PM_POSTOP_GAS = 50_000;

    ShrincsPaymasterHarness internal paymaster;
    string internal vectors;

    address internal OWNER;
    uint256 internal OWNER_PK;

    function setUp() public virtual {
        vm.chainId(CHAIN_ID);
        vectors = vm.readFile(VECTORS);
        (OWNER, OWNER_PK) = makeAddrAndKey("owner");

        ShrincsPaymasterHarness impl = new ShrincsPaymasterHarness();
        vm.etch(PAYMASTER, address(impl).code);
        paymaster = ShrincsPaymasterHarness(payable(PAYMASTER));

        paymaster.harness_setOwner(OWNER);
        paymaster.harness_install(
            _bytes32(".verifierKey.publicKeyCommitment"),
            uint8(vm.parseJsonUint(vectors, ".verifierKey.parameterSetId")),
            MAX_SIG
        );
    }

    function test_setUp() public view virtual {
        assertEq(paymaster.owner(), OWNER);
        (
            bytes32 commitment,
            ShrincsTypes.ParameterSetId parameterSetId,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = paymaster.getShrincsVerifier();
        assertEq(commitment, _bytes32(".verifierKey.publicKeyCommitment"));
        assertEq(
            uint8(parameterSetId),
            uint8(vm.parseJsonUint(vectors, ".verifierKey.parameterSetId"))
        );
        assertEq(keyVersion, 0);
        assertEq(maxSignatures, MAX_SIG);
        assertEq(statefulLeavesUsed, 0);
        assertFalse(paymaster.isStatefulLeafUsed(1));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PARSING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _bytes32(string memory key) internal view returns (bytes32) {
        return _toBytes32(vm.parseJsonBytes(vectors, key));
    }

    function _toBytes32(bytes memory b) internal pure returns (bytes32 out) {
        require(b.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(b, 32))
        }
    }

    /// @dev Parses a `ShrincsTypes.PublicKey` bundle from a JSON object path.
    function _parsePublicKey(
        string memory base
    ) internal view returns (ShrincsTypes.PublicKey memory pk) {
        pk.parameterSetId = ShrincsTypes.ParameterSetId(
            vm.parseJsonUint(vectors, string.concat(base, ".parameterSetId"))
        );
        pk.statefulPublicKey = vm.parseJsonBytes(
            vectors,
            string.concat(base, ".statefulPublicKey")
        );
        pk.publicKeyCommitment = vm.parseJsonBytes(
            vectors,
            string.concat(base, ".publicKeyCommitment")
        );
        pk.pkSeed = vm.parseJsonBytes(vectors, string.concat(base, ".pkSeed"));
        pk.hypertreeRoot = vm.parseJsonBytes(
            vectors,
            string.concat(base, ".hypertreeRoot")
        );
    }

    /// @dev Parses a `ShrincsTypes.StatefulSignature` from a JSON object path.
    function _parseStatefulSignature(
        string memory base
    ) internal view returns (ShrincsTypes.StatefulSignature memory sig) {
        sig.randomizer = _bytes32(string.concat(base, ".randomizer"));
        sig.counter = uint32(
            vm.parseJsonUint(vectors, string.concat(base, ".counter"))
        );
        sig.chains = vm.parseJsonBytes32Array(
            vectors,
            string.concat(base, ".chains")
        );
        sig.authPath = vm.parseJsonBytes32Array(
            vectors,
            string.concat(base, ".authPath")
        );
    }

    /// @dev A `StatefulSignature` whose only meaningful field is `authPath.length` (= the leaf
    ///      index), to drive the pre-verify leaf guards without a real signature.
    function _statefulSigWithLeaf(
        uint256 leaf
    ) internal pure returns (ShrincsTypes.StatefulSignature memory sig) {
        sig.authPath = new bytes32[](leaf);
    }

    /// @dev The leaf-1 sponsorship sig: a structurally valid StatefulSignature (in budget, unused)
    ///      that REACHES `SHRINCS.verifyStateful`. It was signed over the leaf-1 userOp (nonce 1);
    ///      fed against a userOp with a different binding hash (e.g. the default nonce 0) it fails
    ///      verification — exercising the `InvalidSignature` branch.
    function _wrongContextStatefulSig()
        internal
        view
        returns (ShrincsTypes.StatefulSignature memory)
    {
        return _parseStatefulSignature(".cases.sponsor[0].signature");
    }

    /// @dev The installed global verifier public key.
    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".verifierKey");
    }

    /// @dev Rebuilds the exact `PackedUserOperation` that sponsorship case `i` signed (nonce from the
    ///      vector), carrying that case's valid signature. Returns the op + its leaf index.
    function _sponsorUserOp(
        uint256 i
    ) internal view returns (PackedUserOperation memory op, uint32 leaf) {
        string memory base = string.concat(
            ".cases.sponsor[",
            vm.toString(i),
            "]"
        );
        leaf = uint32(vm.parseJsonUint(vectors, string.concat(base, ".leaf")));
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(
            string.concat(base, ".signature")
        );
        op = _userOp(SPONSOR_SENDER, _pmData(_pk(), sig));
        op.nonce = vm.parseJsonUint(vectors, string.concat(base, ".nonce"));
    }

    /// @dev Rebuilds the sponsorship signed over a NON-ZERO validity window (`cases.sponsorWithWindow`),
    ///      carrying the case's `validUntil`/`validAfter` in the `paymasterAndData` prefix exactly as the
    ///      generator signed them. Returns the op, the window bounds, and the leaf index.
    function _sponsorWithWindowUserOp()
        internal
        view
        returns (
            PackedUserOperation memory op,
            uint48 validUntil,
            uint48 validAfter,
            uint32 leaf
        )
    {
        string memory base = ".cases.sponsorWithWindow";
        leaf = uint32(vm.parseJsonUint(vectors, string.concat(base, ".leaf")));
        validUntil = uint48(
            vm.parseJsonUint(vectors, string.concat(base, ".validUntil"))
        );
        validAfter = uint48(
            vm.parseJsonUint(vectors, string.concat(base, ".validAfter"))
        );
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(
            string.concat(base, ".signature")
        );
        op = _userOp(
            SPONSOR_SENDER,
            _paymasterAndData(validUntil, validAfter, _blob(_pk(), sig))
        );
        op.nonce = vm.parseJsonUint(vectors, string.concat(base, ".nonce"));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    USEROP HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ABI-encodes the `(PublicKey, StatefulSignature)` blob that lives at `paymasterAndData[64:]`.
    function _blob(
        ShrincsTypes.PublicKey memory pk,
        ShrincsTypes.StatefulSignature memory sig
    ) internal pure returns (bytes memory) {
        return abi.encode(pk, sig);
    }

    /// @dev Assembles `paymasterAndData`: paymaster(20) | vGas(16) | postOpGas(16) | validUntil(6) |
    ///      validAfter(6) | blob.
    function _paymasterAndData(
        uint48 validUntil,
        uint48 validAfter,
        bytes memory blob
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                PAYMASTER,
                PM_VERIFICATION_GAS,
                PM_POSTOP_GAS,
                validUntil,
                validAfter,
                blob
            );
    }

    /// @dev Convenience: a `paymasterAndData` carrying a given pk+sig with zero validity window.
    function _pmData(
        ShrincsTypes.PublicKey memory pk,
        ShrincsTypes.StatefulSignature memory sig
    ) internal view returns (bytes memory) {
        return _paymasterAndData(0, 0, _blob(pk, sig));
    }

    /// @dev Minimal `PackedUserOperation` for the given sender + paymasterAndData.
    function _userOp(
        address sender,
        bytes memory pmData
    ) internal pure returns (PackedUserOperation memory op) {
        op.sender = sender;
        op.nonce = 0;
        op.initCode = "";
        op.callData = "";
        op.accountGasLimits = bytes32(
            (uint256(100_000) << 128) | uint256(100_000)
        );
        op.preVerificationGas = 21_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(10 gwei));
        op.paymasterAndData = pmData;
        op.signature = "";
    }

    /// @dev Calls `validatePaymasterUserOp` impersonating the EntryPoint.
    function _validate(
        PackedUserOperation memory op
    ) internal returns (bytes memory context, uint256 validationData) {
        vm.prank(ENTRY_POINT);
        return paymaster.validatePaymasterUserOp(op, bytes32(0), 1 ether);
    }
}
