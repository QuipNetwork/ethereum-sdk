// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `initialize`, which installs the owner AND the initial verifier atomically
///      (the paymaster always has a verifier afterward). No signature is verified, so every branch is
///      testable now. Uses a fresh etched harness whose constructor never ran, so the `initializer`
///      path is reachable.
contract ShrincsPaymaster_initialize is ShrincsPaymasterTest {
    ShrincsPaymasterHarness internal bare;
    bytes32 internal constant COMMITMENT = keccak256("verifier-commitment");

    function setUp() public override {
        super.setUp();
        ShrincsPaymasterHarness impl = new ShrincsPaymasterHarness();
        address bareAddr = address(
            uint160(uint256(keccak256("bare-shrincs-paymaster")))
        );
        vm.etch(bareAddr, address(impl).code);
        bare = ShrincsPaymasterHarness(payable(bareAddr));
    }

    function test_initialize_setsOwnerAndVerifier() public {
        bare.initialize(OWNER, COMMITMENT, 0, MAX_SIG);

        assertEq(bare.owner(), OWNER, "owner");
        (
            bytes32 commitment,
            ,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = bare.getShrincsVerifier();
        assertEq(commitment, COMMITMENT, "commitment installed");
        assertEq(keyVersion, 0, "initial epoch 0");
        assertEq(maxSignatures, MAX_SIG, "budget cached");
        assertEq(statefulLeavesUsed, 0, "no leaves used");
        assertFalse(bare.isStatefulLeafUsed(1), "fresh bitmap");
    }

    function test_initialize_emitsEvents() public {
        vm.recordLogs();
        bare.initialize(OWNER, COMMITMENT, 0, MAX_SIG);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool init;
        bool set;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.PaymasterInitialized.selector
            ) init = true;
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.ShrincsVerifierSet.selector
            ) {
                set = true;
                assertEq(
                    logs[i].topics[1],
                    COMMITMENT,
                    "newCommitment indexed"
                );
            }
        }
        assertTrue(init, "PaymasterInitialized emitted");
        assertTrue(set, "ShrincsVerifierSet emitted");
    }

    /// @dev `parameterSetId` must actually be persisted (the success-path test above passes 0, which a
    ///      dropped `$.shrincsParameterSetId =` write would not reveal). Use the `Unsupported` member
    ///      (1) — a valid enum value the getter can safely cast.
    function test_initialize_storesParameterSetId() public {
        bare.initialize(OWNER, COMMITMENT, 1, MAX_SIG);
        (, ShrincsTypes.ParameterSetId parameterSetId, , , ) = bare
            .getShrincsVerifier();
        assertEq(uint8(parameterSetId), 1, "parameterSetId persisted");
    }

    /// @dev Pins the FULL `ShrincsVerifierSet` payload at initialization: previousCommitment is zero
    ///      (first registration), the parameterSetId/maxSignatures echo the args, and the epoch is 0.
    function test_initialize_emitsShrincsVerifierSetFullPayload() public {
        vm.recordLogs();
        bare.initialize(OWNER, COMMITMENT, 1, MAX_SIG);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.ShrincsVerifierSet.selector
            ) {
                found = true;
                assertEq(
                    logs[i].topics[1],
                    COMMITMENT,
                    "newCommitment indexed"
                );
                (
                    bytes32 previousCommitment,
                    uint8 parameterSetId,
                    uint32 maxSignatures,
                    uint256 keyVersion
                ) = abi.decode(logs[i].data, (bytes32, uint8, uint32, uint256));
                assertEq(previousCommitment, bytes32(0), "no prior commitment");
                assertEq(parameterSetId, 1, "parameterSetId in data");
                assertEq(maxSignatures, MAX_SIG, "maxSignatures in data");
                assertEq(keyVersion, 0, "initial epoch in data");
            }
        }
        assertTrue(found, "ShrincsVerifierSet emitted");
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        vm.expectRevert(IShrincsPaymaster.ZeroAddressOwner.selector);
        bare.initialize(address(0), COMMITMENT, 0, MAX_SIG);
    }

    function test_initialize_revertsWhen_zeroCommitment() public {
        vm.expectRevert(IShrincsPaymaster.ZeroCommitment.selector);
        bare.initialize(OWNER, bytes32(0), 0, MAX_SIG);
    }

    function test_initialize_revertsWhen_zeroMaxSignatures() public {
        vm.expectRevert(IShrincsPaymaster.ZeroMaxSignatures.selector);
        bare.initialize(OWNER, COMMITMENT, 0, 0);
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        bare.initialize(OWNER, COMMITMENT, 0, MAX_SIG);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bare.initialize(OWNER, COMMITMENT, 0, MAX_SIG);
    }
}
