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
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `initialize`. Beyond the deterministic shape/suite/commitment
///      validation, it verifies the e3r deploy authorization: the salt commitment cross-check
///      and a main-key deploy signature over the factory-bound deploy context. The mock factory
///      is configured with the deploy context each test needs.
contract ShrincsWallet_initialize is ShrincsWalletTest {
    /// @dev A pristine, un-initialized harness whose immutable FACTORY is the mock factory.
    ShrincsWalletHarness internal bare;

    bytes32 internal constant VAULT_ID = keccak256("bare-vault");
    uint16 internal constant DEPLOY_IDX = 3;

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

        // e3r: publish the deploy context the wallet reads back during `initialize` — the salt
        // commitment matches the installed main commitment, stateful mode at reserved leaf 3.
        factory.setDeployContext(
            address(bare), VAULT_ID, DEPLOY_IDX, IWalletFactory.DeployMode.Stateful, mainCommitment
        );
    }

    /// @dev A valid init payload carrying a stateful deploy authorization for `owner`.
    function _validInitPayloadWithDeploy(address owner) internal view returns (bytes memory) {
        return _initPayloadWithDeploy(
            _statefulDeployAuth(address(factory), VAULT_ID, owner, DEPLOY_IDX)
        );
    }

    function test_initialize_setsState() public {
        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayloadWithDeploy(OWNER));

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

    function test_initialize_emitsWalletInitialized() public {
        vm.recordLogs();
        vm.prank(address(factory));
        bare.initialize(payable(OWNER), _validInitPayloadWithDeploy(OWNER));

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
        bare.initialize(payable(OWNER), _validInitPayloadWithDeploy(OWNER));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bare.initialize(payable(OWNER), _validInitPayloadWithDeploy(OWNER));
        vm.stopPrank();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 e3r DEPLOY AUTHORIZATION              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The salt commitment the factory reports must equal the payload's main commitment.
    function test_initialize_revertsWhen_saltCommitmentMismatch() public {
        // Factory salted the address with a DIFFERENT commitment than the payload installs.
        factory.setDeployContext(
            address(bare),
            VAULT_ID,
            DEPLOY_IDX,
            IWalletFactory.DeployMode.Stateful,
            keccak256("some-other-key")
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        bare.initialize(payable(OWNER), _validInitPayloadWithDeploy(OWNER));
    }

    /// @dev A deploy signature over a DIFFERENT owner than the one being installed is rejected.
    function test_initialize_revertsWhen_deploySigBindsWrongOwner() public {
        bytes memory payload = _initPayloadWithDeploy(
            _statefulDeployAuth(address(factory), VAULT_ID, makeAddr("attacker"), DEPLOY_IDX)
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        bare.initialize(payable(OWNER), payload);
    }

    /// @dev A stateful deploy signature at a leaf other than `quipDeployChainIndex` is rejected.
    function test_initialize_revertsWhen_deploySigWrongLeaf() public {
        bytes memory payload = _initPayloadWithDeploy(
            _statefulDeployAuth(address(factory), VAULT_ID, OWNER, DEPLOY_IDX + 1)
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        bare.initialize(payable(OWNER), payload);
    }

    /// @dev A garbage deploy authorization is rejected.
    function test_initialize_revertsWhen_deploySigInvalid() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        SHRINCS.Signature memory bad;
        bad.authPath = new bytes32[](DEPLOY_IDX); // right leaf, junk signature
        bytes memory payload = _initPayloadWithDeploy(abi.encode(pk, bad));
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        bare.initialize(payable(OWNER), payload);
    }

    /// @dev Stateless-mode factory: a matching stateless deploy signature is accepted.
    function test_initialize_statelessModeSucceeds() public {
        factory.setDeployContext(
            address(bare), VAULT_ID, DEPLOY_IDX, IWalletFactory.DeployMode.Stateless, mainCommitment
        );
        bytes memory payload = _initPayloadWithDeploy(
            _statelessDeployAuth(address(factory), VAULT_ID, OWNER, DEPLOY_IDX)
        );
        vm.prank(address(factory));
        bare.initialize(payable(OWNER), payload);
        assertEq(bare.getShrincsPublicKeyCommitment(), mainCommitment);
    }

    /// @dev A stateful signature is rejected when the factory declares stateless mode.
    function test_initialize_revertsWhen_statefulSigInStatelessMode() public {
        factory.setDeployContext(
            address(bare), VAULT_ID, DEPLOY_IDX, IWalletFactory.DeployMode.Stateless, mainCommitment
        );
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        bare.initialize(payable(OWNER), _validInitPayloadWithDeploy(OWNER));
    }
}
