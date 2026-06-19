// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsUtils} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsUtils.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `initialize`. It verifies NO signature — only deterministic
///      param/commitment validation of the supplied bundle — so its happy path AND every revert
///      are fully testable with the committed key vectors (no regenerated signatures required).
contract ShrincsWallet_initialize is ShrincsWalletTest {
    /// @dev A pristine, un-initialized harness whose immutable FACTORY is the mock factory.
    ShrincsWalletHarness internal bare;

    function setUp() public override {
        super.setUp();
        // Etch the runtime code at a clean address so the constructor's `_disableInitializers`
        // never runs and `initialize` (the `initializer`-gated path) is reachable. The immutable
        // FACTORY is inlined into the runtime code, so the etched copy still points at the mock.
        ShrincsWalletHarness impl = new ShrincsWalletHarness(payable(address(factory)));
        address bareAddr = address(uint160(uint256(keccak256("bare-shrincs-wallet"))));
        vm.etch(bareAddr, address(impl).code);
        bare = ShrincsWalletHarness(payable(bareAddr));
    }

    function test_initialize_setsState() public {
        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayload());

        assertEq(bare.owner(), OWNER, "owner installed");
        assertEq(bare.quipFactory(), address(factory), "factory installed");
        assertEq(bare.getShrincsPublicKeyCommitment(), _bytes32(".mainKey.publicKeyCommitment"), "main commitment");
        assertEq(bare.getErc1271Commitment(), _bytes32(".erc1271Key.publicKeyCommitment"), "erc1271 commitment");
        assertEq(
            uint8(bare.getParameterSetId()), uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")), "paramId"
        );
        assertEq(bare.maxSignatures(), MAX_SIG, "maxSignatures decoded from the bundle");
        assertEq(bare.keyVersion(), 0, "epoch starts at 0");
        assertEq(bare.statefulLeavesUsed(), 0, "no leaves used");
        assertFalse(bare.isStatefulLeafUsed(1), "epoch-0 bitmap empty");
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
                assertEq(logs[i].topics[3], _bytes32(".mainKey.publicKeyCommitment"), "commitment indexed");
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
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        bytes memory payload = _buildInitPayload(
            _bytes32(".mainKey.publicKeyCommitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")),
            bytes32(0), // zero ERC-1271 commitment
            0
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_invalidParams() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        // Declared parameterSetId = Unsupported (1) ⇒ validParams returns false.
        bytes memory payload = _buildInitPayload(
            _bytes32(".mainKey.publicKeyCommitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            1,
            _bytes32(".erc1271Key.publicKeyCommitment"),
            0
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_declaredCommitmentMismatch() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        // Valid params + valid bundle, but the standalone declared commitment is wrong.
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _bytes32(".mainKey.pkSeed"),
            pk,
            uint8(vm.parseJsonUint(vectors, ".mainKey.parameterSetId")),
            _bytes32(".erc1271Key.publicKeyCommitment"),
            0
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        bare.initialize(payable(OWNER), payload);
    }

    function test_initialize_revertsWhen_zeroMaxSignatures() public {
        ShrincsTypes.PublicKey memory pk = _parsePublicKey(".mainKey");
        // Zero the trailing 4-byte maxSignatures of the 68-byte stateful key, then recompute the
        // bundle commitment so validParams/commitment checks pass and the explicit guard fires.
        bytes memory spk = pk.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0;
        bytes32 newCommit =
            ShrincsUtils.publicKeyCommitmentFromParts(ShrincsTypes.ParameterSetId(0), spk, pk.pkSeed, pk.hypertreeRoot);
        pk.statefulPublicKey = spk;
        pk.publicKeyCommitment = abi.encodePacked(newCommit);
        bytes memory payload = _buildInitPayload(
            newCommit, _bytes32(".mainKey.pkSeed"), pk, 0, _bytes32(".erc1271Key.publicKeyCommitment"), 0
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
