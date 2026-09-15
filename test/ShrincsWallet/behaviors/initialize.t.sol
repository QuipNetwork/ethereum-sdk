// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `initialize`: the deterministic shape/suite/commitment validation.
///      Every branch reachable through the production path is driven through the REAL
///      `factory.deployLatestWalletProxy` (the wallet's revert bubbles through the deploy);
///      only the guards the factory flow can never reach (wrong caller, zero owner) run
///      against a real, un-initialized ERC-1967 proxy deployed outside the factory.
contract ShrincsWallet_initialize is ShrincsWalletTest {
    /// @dev A real, un-initialized ERC-1967 proxy over the vetted implementation, deployed
    ///      OUTSIDE the factory on purpose: the constructor's `_disableInitializers` only locks
    ///      the bare implementation, so `initialize` is reachable here — exercising the guards
    ///      the factory pre-empts on its own side.
    ShrincsWalletHarness internal bare;

    // ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public override {
        super.setUp();
        bare = ShrincsWalletHarness(payable(LibClone.deployERC1967(address(walletImplementation))));
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertEq(
            address(uint160(uint256(vm.load(address(bare), IMPL_SLOT)))),
            address(walletImplementation),
            "side proxy points at the vetted implementation"
        );
        assertEq(bare.owner(), address(0), "side proxy un-initialized");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       HELPERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a wallet through the real factory as `owner` — the production
    ///      `initialize` path end to end (CREATE3 + `commitmentOf` + `initialize`).
    function _deployVia(bytes32 commitment, address owner, bytes memory payload)
        internal
        returns (address)
    {
        vm.prank(owner);
        return factory.deployLatestWalletProxy(commitment, payable(owner), payload);
    }

    /// @dev Fresh main + ERC-1271 bundles for `seed`, plus both commitments (the 1271 bundle
    ///      is re-derived deterministically from the same seed `_freshInitPayload` uses).
    function _freshWalletParams(bytes memory seed)
        internal
        view
        returns (bytes memory payload, bytes32 mainC, bytes32 e1271C)
    {
        (payload, mainC) = _freshInitPayload(seed);
        e1271C = _commitment32(_freshErc1271Pk(seed));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     SUCCESS PATHS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_initialize_setsState() public {
        (bytes memory payload, bytes32 mainC, bytes32 e1271C) = _freshWalletParams("init-sets-state");
        address addr = _deployVia(Codec.v1Commitment(mainC, e1271C, OWNER), OWNER, payload);
        ShrincsWalletHarness w = ShrincsWalletHarness(payable(addr));

        assertEq(w.owner(), OWNER, "owner installed");
        assertEq(w.walletFactory(), address(factory), "factory installed");
        assertEq(w.getShrincsPublicKeyCommitment(), mainC, "main commitment");
        assertEq(w.getErc1271PublicKeyCommitment(), e1271C, "erc1271 commitment");
        assertEq(w.getHashSuite(), HashSuite.HASH_SUITE_ID, "hash suite");
        assertEq(w.getErc1271HashSuite(), HashSuite.HASH_SUITE_ID, "erc1271 hash suite");
        assertEq(w.maxSignatures(), MAX_SIG, "maxSignatures decoded from the bundle");
        assertEq(w.keyVersion(), 0, "epoch starts at 0");
        assertEq(w.statefulLeavesUsed(), 0, "no leaves used");
        assertFalse(w.isStatefulLeafUsed(1), "epoch-0 bitmap empty");
    }

    function test_initialize_spendsInstalledTrees() public {
        (bytes memory payload, bytes32 mainC, bytes32 e1271C) = _freshWalletParams("init-spends-trees");
        // Re-derive the deterministic main bundle to compute its tree identities.
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen("init-spends-trees", MAX_SIG);
        assertTrue(ok, "keygen");

        address addr = _deployVia(Codec.v1Commitment(mainC, e1271C, OWNER), OWNER, payload);
        ShrincsWalletHarness w = ShrincsWalletHarness(payable(addr));

        assertTrue(w.harness_isStatefulTreeSpent(_treeId(pk.statefulPublicKey)), "initialize spends the stateful tree");
        assertTrue(w.harness_isStatelessTreeSpent(_statelessId(pk)), "initialize spends the stateless tree");
    }

    function test_initialize_spendsErc1271Trees() public {
        (bytes memory payload, bytes32 mainC, bytes32 e1271C) = _freshWalletParams("init-spends-1271");
        SHRINCS.PublicKey memory epk = _freshErc1271Pk("init-spends-1271");

        address addr = _deployVia(Codec.v1Commitment(mainC, e1271C, OWNER), OWNER, payload);
        ShrincsWalletHarness w = ShrincsWalletHarness(payable(addr));

        assertTrue(w.harness_isStatefulTreeSpent(_treeId(epk.statefulPublicKey)), "1271 stateful spent");
        assertTrue(w.harness_isStatelessTreeSpent(_statelessId(epk)), "1271 stateless spent");
    }

    function test_initialize_emitsWalletInitialized() public {
        (bytes memory payload, bytes32 mainC, bytes32 e1271C) = _freshWalletParams("init-emits");

        vm.recordLogs();
        _deployVia(Codec.v1Commitment(mainC, e1271C, OWNER), OWNER, payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.WalletInitialized.selector) {
                found = true;
                assertEq(address(uint160(uint256(logs[i].topics[1]))), address(factory), "factory indexed");
                assertEq(address(uint160(uint256(logs[i].topics[2]))), OWNER, "owner indexed");
                assertEq(logs[i].topics[3], mainC, "commitment indexed");
            }
        }
        assertTrue(found, "WalletInitialized not emitted");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       REVERTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_initialize_revertsWhen_callerNotFactory() public {
        vm.prank(makeAddr("notFactory"));
        vm.expectRevert(IShrincsWallet.InvalidFactory.selector);
        bare.initialize(payable(OWNER), _validInitPayload());
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        // Unreachable through the factory (it rejects a zero `to` on its own side first), so
        // the wallet-level guard is exercised directly on the un-initialized proxy.
        vm.prank(address(factory));
        vm.expectRevert(IShrincsWallet.ZeroAddressOwner.selector);
        bare.initialize(payable(address(0)), _validInitPayload());
    }

    function test_initialize_revertsWhen_invalidErc1271Bundle() public {
        SHRINCS.PublicKey memory epk = erc1271Pk;
        epk.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-erc1271-commitment"));
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(mainPk.pkSeed), _mainPk(), HashSuite.HASH_SUITE_ID, epk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        _deployVia(keccak256("init-bad-1271"), OWNER, payload);
    }

    /// @dev Regression (audit): the ERC-1271 slot may never be the main key. Equal bundles trip
    ///      the registry on the 1271 bundle's trees (spent by the main bundle in the same call,
    ///      before the factory-side identity check is reached).
    function test_initialize_revertsWhen_erc1271BundleEqualsMain() public {
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(mainPk.pkSeed), _mainPk(), HashSuite.HASH_SUITE_ID, _mainPk(), HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        _deployVia(keccak256("init-1271-equals-main"), OWNER, payload);
    }

    /// @dev Regression (audit): a 1271 bundle with a FRESH stateful subkey but the main key's
    ///      stateless root — a different commitment over the same recovery authority — is
    ///      rejected on the stateless registry. A commitment-equality check would let this through.
    function test_initialize_revertsWhen_erc1271SharesMainStatelessRoot() public {
        SHRINCS.PublicKey memory epk = _bundleSharingStatelessRoot("init-1271-shares-root", mainPk);
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(mainPk.pkSeed), _mainPk(), HashSuite.HASH_SUITE_ID, epk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        _deployVia(keccak256("init-1271-shares-root"), OWNER, payload);
    }

    function test_initialize_revertsWhen_unsupportedHashSuite() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            SHRINCS.HASH_SUITE_UNSUPPORTED,
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        _deployVia(keccak256("init-bad-suite"), OWNER, payload);
    }

    function test_initialize_revertsWhen_unsupportedErc1271HashSuite() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory payload = _buildInitPayload(
            mainCommitment,
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Pk,
            SHRINCS.HASH_SUITE_UNSUPPORTED
        );
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        _deployVia(keccak256("init-bad-1271-suite"), OWNER, payload);
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
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        _deployVia(keccak256("init-invalid-bundle"), OWNER, payload);
    }

    function test_initialize_revertsWhen_declaredCommitmentMismatch() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        // Valid bundle, but the standalone declared commitment is wrong.
        bytes memory payload = _buildInitPayload(
            keccak256("wrong-commitment"),
            _toBytes32(pk.pkSeed),
            pk,
            HashSuite.HASH_SUITE_ID,
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        _deployVia(keccak256("init-declared-mismatch"), OWNER, payload);
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
            erc1271Pk,
            HashSuite.HASH_SUITE_ID
        );

        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        _deployVia(keccak256("init-zero-max-sigs"), OWNER, payload);
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        // The factory-deployed base wallet is initialized; the `initializer` modifier fires
        // before any body check, whoever the caller is.
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        wallet.initialize(payable(OWNER), _validInitPayload());
    }
}
