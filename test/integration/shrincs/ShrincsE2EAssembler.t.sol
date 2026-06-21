// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

/// @title ShrincsE2E vector assembler
/// @dev Fork-independent helpers shared by the e2e suite: parses the combined wallet+paymaster e2e
///      vectors and rebuilds the exact `PackedUserOperation` each case was signed over. Kept separate
///      from the forking base so the encoding cross-check (`getUserOpHash`/`abi.encode` self-consistency)
///      can run with no RPC. Holds NO fork/etch logic.
abstract contract ShrincsE2EAssembler is Test {
    string internal constant VECTORS =
        "test/test_vectors/shrincs_e2e_sphincs_256s_keccak.json";

    // Must match the generator's constants.
    address internal constant WALLET =
        0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
    address internal constant PAYMASTER =
        0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2;
    address internal constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant RECIPIENT =
        0x000000000000000000000000000000000000b0b0;
    address internal constant CALL_TARGET =
        0x000000000000000000000000000000000000cA11;
    uint256 internal constant CHAIN_ID = 31337;
    uint32 internal constant MAX_SIG = 8;

    bytes4 internal constant EXECUTE_SELECTOR =
        bytes4(keccak256("execute(address,uint256,bytes)"));

    string internal vectors;

    function setUp() public virtual {
        vectors = vm.readFile(VECTORS);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    OP ASSEMBLY                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Rebuilds the exact `PackedUserOperation` case `name` was signed over, using the default
    ///      wallet key (`.walletKey`) and the paymaster key implied by the case (`.verifierKey`, or
    ///      `.verifierKey2` for the rotation case).
    function _assembleOp(
        string memory name
    ) internal view returns (PackedUserOperation memory op) {
        return _assembleOp(name, ".walletKey", _pmKeyPath(name));
    }

    /// @dev Rebuilds case `name` with explicit wallet/paymaster public-key JSON paths (for rotation
    ///      flows where the active key differs from the default).
    function _assembleOp(
        string memory name,
        string memory walletKeyPath,
        string memory pmKeyPath
    ) internal view returns (PackedUserOperation memory op) {
        string memory b = string.concat(".cases.", name);

        bytes memory callData = abi.encodeWithSelector(
            EXECUTE_SELECTOR,
            vm.parseJsonAddress(vectors, string.concat(b, ".target")),
            vm.parseUint(
                vm.parseJsonString(vectors, string.concat(b, ".value"))
            ),
            vm.parseJsonBytes(vectors, string.concat(b, ".data"))
        );

        bytes memory pmAndData = abi.encodePacked(
            PAYMASTER,
            uint128(vm.parseJsonUint(vectors, ".gas.paymasterVerificationGas")),
            uint128(vm.parseJsonUint(vectors, ".gas.paymasterPostOpGas")),
            uint48(vm.parseJsonUint(vectors, string.concat(b, ".validUntil"))),
            uint48(vm.parseJsonUint(vectors, string.concat(b, ".validAfter"))),
            abi.encode(
                _parsePublicKey(pmKeyPath),
                _parseStatefulSignature(string.concat(b, ".paymasterSignature"))
            )
        );

        op = PackedUserOperation({
            sender: WALLET,
            nonce: vm.parseJsonUint(vectors, string.concat(b, ".nonce")),
            initCode: "",
            callData: callData,
            accountGasLimits: _bytes32(".gas.accountGasLimits"),
            preVerificationGas: vm.parseJsonUint(
                vectors,
                ".gas.preVerificationGas"
            ),
            gasFees: _bytes32(".gas.gasFees"),
            paymasterAndData: pmAndData,
            signature: abi.encode(
                _parsePublicKey(walletKeyPath),
                _parseStatefulSignature(string.concat(b, ".walletSignature"))
            )
        });
    }

    /// @dev The canonical ERC-4337 v0.7 userOpHash (pure; mirrors `EntryPoint.getUserOpHash`). Used by
    ///      the no-fork cross-check; on the fork it is additionally compared to the live EntryPoint.
    function _computeUserOpHash(
        PackedUserOperation memory op
    ) internal pure returns (bytes32) {
        bytes32 inner = keccak256(
            abi.encode(
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                keccak256(op.paymasterAndData)
            )
        );
        return keccak256(abi.encode(inner, ENTRY_POINT, CHAIN_ID));
    }

    function _pmKeyPath(
        string memory name
    ) internal pure returns (string memory) {
        if (
            keccak256(bytes(name)) ==
            keccak256(bytes("paymasterRotationNewKey"))
        ) {
            return ".verifierKey2";
        }
        return ".verifierKey";
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PARSING HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _vectorUserOpHash(
        string memory name
    ) internal view returns (bytes32) {
        return _bytes32(string.concat(".cases.", name, ".userOpHash"));
    }

    function _bytes32(string memory key) internal view returns (bytes32) {
        return _toBytes32(vm.parseJsonBytes(vectors, key));
    }

    function _toBytes32(bytes memory bts) internal pure returns (bytes32 out) {
        require(bts.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(bts, 32))
        }
    }

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

    function _parseStatefulRotationTarget(
        string memory base
    ) internal view returns (ShrincsTypes.StatefulRotationTarget memory t) {
        t.parameterSetId = ShrincsTypes.ParameterSetId(
            vm.parseJsonUint(vectors, string.concat(base, ".parameterSetId"))
        );
        t.statefulPublicKey = vm.parseJsonBytes(
            vectors,
            string.concat(base, ".statefulPublicKey")
        );
        t.publicKeyCommitment = vm.parseJsonBytes(
            vectors,
            string.concat(base, ".publicKeyCommitment")
        );
    }

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
}
