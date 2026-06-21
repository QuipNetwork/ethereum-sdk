// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsE2EAssembler} from "./ShrincsE2EAssembler.t.sol";

/// @dev No-fork validation that the Rust generator's hand-rolled ABI encoding + userOpHash match what
///      Solidity produces. If the `abi.encode(PublicKey, StatefulSignature)` byte layout or the
///      canonical v0.7 userOpHash drifts, this fails immediately — long before any fork/handleOps.
///      Reproduces the assembled `paymasterAndData` and asserts it keccak-matches the baked bytes, and
///      that the pure userOpHash equals the baked `userOpHash` every case was signed over.
contract ShrincsE2E_encodingCrossCheck is ShrincsE2EAssembler {
    function _check(string memory name) internal view {
        PackedUserOperation memory op = _assembleOp(name);

        // The reconstructed paymasterAndData must be byte-identical to what the generator hashed.
        bytes memory expectedPmData = vm.parseJsonBytes(
            vectors,
            string.concat(".cases.", name, ".paymasterAndData")
        );
        assertEq(
            op.paymasterAndData.length,
            expectedPmData.length,
            string.concat(name, ": paymasterAndData length")
        );
        assertEq(
            keccak256(op.paymasterAndData),
            keccak256(expectedPmData),
            string.concat(
                name,
                ": paymasterAndData bytes (abi.encode blob drift)"
            )
        );

        // The pure canonical userOpHash must equal the baked one the wallet signed.
        assertEq(
            _computeUserOpHash(op),
            _vectorUserOpHash(name),
            string.concat(name, ": userOpHash")
        );

        // And the callData must reproduce exactly (selector + abi.encode(target,value,data)).
        bytes memory expectedCallData = vm.parseJsonBytes(
            vectors,
            string.concat(".cases.", name, ".callData")
        );
        assertEq(
            keccak256(op.callData),
            keccak256(expectedCallData),
            string.concat(name, ": callData")
        );
    }

    function test_crossCheck_sponsoredEthTransfer() public view {
        _check("sponsoredEthTransfer");
    }

    function test_crossCheck_sponsoredContractCall() public view {
        _check("sponsoredContractCall");
    }

    function test_crossCheck_outOfOrderA() public view {
        _check("outOfOrderA");
    }

    function test_crossCheck_outOfOrderB() public view {
        _check("outOfOrderB");
    }

    function test_crossCheck_staleWalletLeafReplay() public view {
        _check("staleWalletLeafReplay");
    }

    function test_crossCheck_badPaymasterContext() public view {
        _check("badPaymasterContext");
    }

    function test_crossCheck_windowNotDue() public view {
        _check("windowNotDue");
    }

    function test_crossCheck_windowExpired() public view {
        _check("windowExpired");
    }

    function test_crossCheck_paymasterRotationNewKey() public view {
        _check("paymasterRotationNewKey");
    }
}
