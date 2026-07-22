// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `initialize`, which installs the owner AND the initial verifier atomically
///      (the paymaster always has a verifier afterward). The full public-key bundle is presented and
///      the commitment + leaf budget are DERIVED from it (never trusted parameters), so these tests
///      feed the real keygen bundle from the base and pin the derived values. Uses a fresh etched
///      harness whose constructor never ran, so the `initializer` path is reachable.
contract ShrincsPaymaster_initialize is ShrincsPaymasterTest {
    ShrincsPaymasterHarness internal bare;
    uint32 internal constant SUITE = HashSuite.HASH_SUITE_ID;

    function setUp() public override {
        super.setUp();
        ShrincsPaymasterHarness impl =
            new ShrincsPaymasterHarness(address(shrincsVerifier));
        address bareAddr = address(
            uint160(uint256(keccak256("bare-shrincs-paymaster")))
        );
        vm.etch(bareAddr, address(impl).code);
        bare = ShrincsPaymasterHarness(payable(bareAddr));
    }

    function test_initialize_setsOwnerAndDerivedVerifier() public {
        bare.initialize(OWNER, _pk(), SUITE);

        assertEq(bare.owner(), OWNER, "owner");
        (
            bytes32 commitment,
            ,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = bare.getShrincsVerifier();
        assertEq(commitment, verifierCommitment, "commitment derived from bundle");
        assertEq(keyVersion, 0, "initial epoch 0");
        assertEq(maxSignatures, MAX_SIG, "budget decoded from key bytes");
        assertEq(bare.remainingStatefulSignatures(), MAX_SIG, "full budget remaining");
        assertEq(statefulLeavesUsed, 0, "no leaves used");
        assertFalse(bare.isStatefulLeafUsed(1), "fresh bitmap");
    }

    function test_initialize_emitsEvents() public {
        vm.recordLogs();
        bare.initialize(OWNER, _pk(), SUITE);

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
                    verifierCommitment,
                    "newCommitment indexed"
                );
            }
        }
        assertTrue(init, "PaymasterInitialized emitted");
        assertTrue(set, "ShrincsVerifierSet emitted");
    }

    /// @dev The hash suite is not stored (initialize rejects everything but keccak-256), so the
    ///      view must echo the constant.
    function test_initialize_reportsHashSuite() public {
        bare.initialize(OWNER, _pk(), SUITE);
        (, uint32 hashSuite, , , ) = bare.getShrincsVerifier();
        assertEq(hashSuite, SUITE, "hashSuite reported");
    }

    /// @dev A hash suite the on-chain library does not verify must be rejected at install time.
    function test_initialize_revertsWhen_unsupportedHashSuite() public {
        vm.expectRevert(IShrincsPaymaster.UnsupportedHashSuite.selector);
        bare.initialize(OWNER, _pk(), SHRINCS.HASH_SUITE_UNSUPPORTED);
    }

    /// @dev Pins the FULL `ShrincsVerifierSet` payload at initialization: previousCommitment is zero
    ///      (first registration), commitment/maxSignatures are the DERIVED values, and the epoch is 0.
    function test_initialize_emitsShrincsVerifierSetFullPayload() public {
        vm.recordLogs();
        bare.initialize(OWNER, _pk(), SUITE);

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
                    verifierCommitment,
                    "newCommitment indexed"
                );
                (
                    bytes32 previousCommitment,
                    uint32 hashSuite,
                    uint32 maxSignatures,
                    uint256 keyVersion
                ) = abi.decode(logs[i].data, (bytes32, uint32, uint32, uint256));
                assertEq(previousCommitment, bytes32(0), "no prior commitment");
                assertEq(hashSuite, SUITE, "hashSuite in data");
                assertEq(maxSignatures, MAX_SIG, "decoded maxSignatures in data");
                assertEq(keyVersion, 0, "initial epoch in data");
            }
        }
        assertTrue(found, "ShrincsVerifierSet emitted");
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        vm.expectRevert(IShrincsPaymaster.ZeroAddressOwner.selector);
        bare.initialize(address(0), _pk(), SUITE);
    }

    /// @dev A stateful subkey of the wrong fixed width fails `validPublicKey`'s shape check.
    function test_initialize_revertsWhen_malformedStatefulKey() public {
        SHRINCS.PublicKey memory pk = _pk();
        bytes memory truncated = new bytes(SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES - 1);
        for (uint256 i = 0; i < truncated.length; i++) {
            truncated[i] = pk.statefulPublicKey[i];
        }
        pk.statefulPublicKey = truncated;
        vm.expectRevert(IShrincsPaymaster.CommitmentMismatch.selector);
        bare.initialize(OWNER, pk, SUITE);
    }

    /// @dev An embedded commitment that does not recompute over the bundle is rejected — a typo'd
    ///      bundle can never install a commitment nobody can sign for.
    function test_initialize_revertsWhen_tamperedCommitment() public {
        SHRINCS.PublicKey memory pk = _pk();
        pk.publicKeyCommitment[0] ^= 0xff;
        vm.expectRevert(IShrincsPaymaster.CommitmentMismatch.selector);
        bare.initialize(OWNER, pk, SUITE);
    }

    /// @dev A bundle whose key bytes encode a zero leaf budget (bytes [64,68) of the stateful
    ///      subkey) can never authorize a signature; the embedded commitment is recomputed so the
    ///      bundle passes `validPublicKey` and the revert isolates the budget check.
    function test_initialize_revertsWhen_zeroDecodedMaxSignatures() public {
        SHRINCS.PublicKey memory pk = _pk();
        for (uint256 i = 64; i < 68; i++) {
            pk.statefulPublicKey[i] = 0;
        }
        bytes32 recomputed = SHRINCS.publicKeyCommitmentFromParts(
            pk.statefulPublicKey,
            pk.pkSeed,
            pk.hypertreeRoot
        );
        pk.publicKeyCommitment = abi.encodePacked(recomputed);
        vm.expectRevert(IShrincsPaymaster.ZeroMaxSignatures.selector);
        bare.initialize(OWNER, pk, SUITE);
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        bare.initialize(OWNER, _pk(), SUITE);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bare.initialize(OWNER, _pk(), SUITE);
    }
}
