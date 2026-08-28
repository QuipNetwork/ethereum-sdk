// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `initialize`: the deterministic shape/suite/commitment validation.
contract ShrincsWallet_initialize is ShrincsWalletTest {
    /// @dev A pristine, un-initialized harness whose immutable FACTORY is the mock factory.
    ShrincsWalletHarness internal bare;

    function setUp() public override {
        super.setUp();
        // Etch the runtime code at a clean address so the constructor's `_disableInitializers`
        // never runs and `initialize` (the `initializer`-gated path) is reachable. The immutable
        // FACTORY is inlined into the runtime code, so the etched copy still points at the mock.
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        address bareAddr = address(uint160(uint256(keccak256("bare-shrincs-wallet"))));
        vm.etch(bareAddr, address(impl).code);
        bare = ShrincsWalletHarness(payable(bareAddr));
        factory.setCommitment(bareAddr, Codec.v1Commitment(mainCommitment, erc1271Commitment, OWNER));
    }

    function test_initialize_setsState() public {
        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayload());

        assertEq(bare.owner(), OWNER, "owner installed");
        assertEq(bare.walletFactory(), address(factory), "factory installed");
        assertEq(bare.getShrincsPublicKeyCommitment(), mainCommitment, "main commitment");
        assertEq(bare.getErc1271Commitment(), erc1271Commitment, "erc1271 commitment");
        assertEq(bare.getHashSuite(), HashSuite.HASH_SUITE_ID, "hash suite");
        assertEq(bare.getErc1271HashSuite(), HashSuite.HASH_SUITE_ID, "erc1271 hash suite");
        assertEq(bare.maxSignatures(), MAX_SIG, "maxSignatures decoded from the bundle");
        assertEq(bare.keyVersion(), 0, "epoch starts at 0");
        assertEq(bare.statefulLeavesUsed(), 0, "no leaves used");
        assertFalse(bare.isStatefulLeafUsed(1), "epoch-0 bitmap empty");
    }

    function test_initialize_spendsInstalledTrees() public {
        bytes32 statefulId = _treeId(mainPk.statefulPublicKey);
        bytes32 statelessId = _statelessId(mainPk);
        assertFalse(bare.harness_isStatefulTreeSpent(statefulId), "stateful unspent before init");
        assertFalse(bare.harness_isStatelessTreeSpent(statelessId), "stateless unspent before init");

        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayload());

        assertTrue(bare.harness_isStatefulTreeSpent(statefulId), "initialize spends the stateful tree");
        assertTrue(bare.harness_isStatelessTreeSpent(statelessId), "initialize spends the stateless tree");
    }

    function test_initialize_emitsWalletInitialized() public {
        vm.recordLogs();
        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayload());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.WalletInitialized.selector) {
                found = true;
                assertEq(address(uint160(uint256(logs[i].topics[1]))), address(factory), "factory indexed");
                assertEq(address(uint160(uint256(logs[i].topics[2]))), OWNER, "owner indexed");
                assertEq(logs[i].topics[3], mainCommitment, "commitment indexed");
            }
        }
        assertTrue(found, "WalletInitialized not emitted");
    }

    function test_initialize_revertsWhen_callerNotFactory() public {
        vm.prank(makeAddr("notFactory"));
        vm.expectRevert(IShrincsWallet.InvalidFactory.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.ZeroAddressOwner.selector);
        bare.initialize(payable(address(0)), _validInitPayload());
    }

    function test_initialize_revertsWhen_zeroErc1271Commitment() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            bytes32(0), // zero ERC-1271 commitment
            HashSuite.HASH_SUITE_ID
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_unsupportedHashSuite() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            SHRINCS.HASH_SUITE_UNSUPPORTED,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_unsupportedErc1271HashSuite() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            SHRINCS.HASH_SUITE_UNSUPPORTED
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_invalidBundle() public {
        // Corrupt the bundle's embedded commitment so `validPublicKey` fails its recompute check.
        SHRINCS.PublicKey memory pk = _mainPk();
        pk.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-embedded-commitment"));
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_declaredCommitmentMismatch() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        // Valid bundle, but the standalone declared commitment is wrong.
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_zeroMaxSignatures() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        // Zero the trailing 4-byte maxSignatures of the 68-byte stateful key, then recompute the
        // bundle commitment so the shape/commitment checks pass and the explicit guard fires.
        bytes memory spk = pk.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0;
        bytes32 newCommit = SHRINCS.publicKeyCommitmentFromParts(spk, pk.pkSeed, pk.hypertreeRoot);
        pk.statefulPublicKey = spk;
        pk.publicKeyCommitment = abi.encodePacked(newCommit);
        bytes memory payload = _buildInitPayload(
            newCommit,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );

        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        vm.startPrank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayload());
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
        vm.stopPrank();
    }

}
