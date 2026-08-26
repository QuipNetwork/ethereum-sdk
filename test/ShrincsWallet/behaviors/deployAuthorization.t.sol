// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWallet} from "../../../contracts/shrincs/ShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev End-to-end e3r deploy-authorization tests: a REAL `WalletFactory` deploying a REAL
///      `ShrincsWallet` through CREATE3, exercising the commitment-bound salt and the main-key
///      deploy signature `initialize` requires. Reuses the base's generated keys, pinned SHRINCS
///      verifier, and deploy-auth helpers.
contract ShrincsWallet_deployAuthorization is ShrincsWalletTest {
    WalletFactory internal realFactory;
    address internal ADMIN;

    bytes32 internal constant VAULT_ID = keccak256("e3r-vault");
    uint16 internal constant DEPLOY_IDX = 3;

    function setUp() public override {
        super.setUp();
        ADMIN = makeAddr("factory-admin");

        // Real factory: implementation + ERC-1967 proxy (the proxy is the factory identity the
        // wallet immutable and CREATE3 addressing derive from).
        WalletFactory factoryImpl = new WalletFactory(0.1 ether);
        realFactory = WalletFactory(payable(LibClone.deployERC1967(address(factoryImpl))));
        realFactory.initialize(payable(ADMIN));

        // Vet a real ShrincsWallet implementation pinned to THIS factory + the base's verifier.
        ShrincsWalletHarness impl =
            new ShrincsWalletHarness(payable(address(realFactory)), address(shrincsVerifier));
        vm.startPrank(ADMIN);
        realFactory.vetImplementation(address(impl));
        realFactory.setDeployConfig(DEPLOY_IDX, IWalletFactory.DeployMode.Stateful);
        vm.stopPrank();
    }

    function _salt(bytes32 vaultId, bytes32 commitment) internal pure returns (bytes32) {
        return keccak256(abi.encode(vaultId, commitment));
    }

    function _predict(bytes32 vaultId, bytes32 commitment) internal view returns (address) {
        return CREATE3.predictDeterministicAddress(_salt(vaultId, commitment), address(realFactory));
    }

    /// @dev A valid stateful deploy authorization for `owner`, bound to the real factory.
    function _deployAuthFor(address owner) internal view returns (bytes memory) {
        return _statefulDeployAuth(address(realFactory), VAULT_ID, owner, DEPLOY_IDX);
    }

    function test_deploy_succeedsAtCommitmentBoundAddress() public {
        address predicted = _predict(VAULT_ID, mainCommitment);
        bytes memory payload = _initPayloadWithDeploy(_deployAuthFor(OWNER));

        address walletAddr =
            realFactory.deployLatestWalletProxy(VAULT_ID, mainCommitment, payable(OWNER), payload);

        assertEq(walletAddr, predicted, "lands at salt(vaultId, commitment) address");
        assertEq(realFactory.wallets(_salt(VAULT_ID, mainCommitment)), walletAddr, "registry keyed by salt");
        assertEq(realFactory.vaultIdOf(walletAddr), VAULT_ID, "reverse vaultId kept raw");
        assertEq(ShrincsWallet(payable(walletAddr)).owner(), OWNER, "owner installed");
        assertEq(
            ShrincsWallet(payable(walletAddr)).getShrincsPublicKeyCommitment(),
            mainCommitment,
            "main commitment installed"
        );
        // The deploy leaf is NOT a signing leaf and no signing budget was consumed.
        assertEq(ShrincsWallet(payable(walletAddr)).statefulLeavesUsed(), 0, "no leaf consumed");
    }

    function test_deploy_revertsWhen_absentDeploySig() public {
        // 6-field payload with an EMPTY deployAuth blob.
        bytes memory payload = _initPayloadWithDeploy("");
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        realFactory.deployLatestWalletProxy(VAULT_ID, mainCommitment, payable(OWNER), payload);
    }

    function test_deploy_revertsWhen_deploySigBindsOtherOwner() public {
        // Valid signature, but bound to a different owner than the one being installed.
        bytes memory payload = _initPayloadWithDeploy(_deployAuthFor(makeAddr("other")));
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        realFactory.deployLatestWalletProxy(VAULT_ID, mainCommitment, payable(OWNER), payload);
    }

    /// @dev An attacker who knows the victim's PUBLIC commitment (so can target the victim's
    ///      address) still cannot deploy there without a deploy signature that binds THEIR owner.
    function test_deploy_attackerCannotHijackCommitmentAddress() public {
        address attacker = makeAddr("attacker");
        address victimAddr = _predict(VAULT_ID, mainCommitment);

        // Attacker reuses the public commitment (targets the victim address) but has no valid
        // deploy signature binding themselves as owner — the best they can forge is garbage.
        SHRINCS.PublicKey memory pk = _mainPk();
        SHRINCS.Signature memory junk;
        junk.authPath = new bytes32[](DEPLOY_IDX);
        bytes memory payload = _initPayloadWithDeploy(abi.encode(pk, junk));

        vm.prank(attacker);
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        realFactory.deployLatestWalletProxy(VAULT_ID, mainCommitment, payable(attacker), payload);

        assertEq(victimAddr.code.length, 0, "victim address remains undeployed");
    }

    /// @dev The salt commitment must equal the main commitment the payload installs.
    function test_deploy_revertsWhen_saltCommitmentMismatch() public {
        bytes32 wrongCommitment = keccak256("not-the-installed-key");
        // Deploy sig is valid for the real (installed) commitment, but the factory salts with a
        // DIFFERENT commitment, so the wallet's cross-check fails.
        bytes memory payload = _initPayloadWithDeploy(_deployAuthFor(OWNER));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        realFactory.deployLatestWalletProxy(VAULT_ID, wrongCommitment, payable(OWNER), payload);
    }

    function test_deploy_statelessModeSucceeds() public {
        vm.prank(ADMIN);
        realFactory.setDeployConfig(DEPLOY_IDX, IWalletFactory.DeployMode.Stateless);

        bytes memory payload = _initPayloadWithDeploy(
            _statelessDeployAuth(address(realFactory), VAULT_ID, OWNER, DEPLOY_IDX)
        );
        address walletAddr =
            realFactory.deployLatestWalletProxy(VAULT_ID, mainCommitment, payable(OWNER), payload);
        assertEq(walletAddr, _predict(VAULT_ID, mainCommitment));
    }

    function test_deploy_revertsWhen_statefulSigInStatelessMode() public {
        vm.prank(ADMIN);
        realFactory.setDeployConfig(DEPLOY_IDX, IWalletFactory.DeployMode.Stateless);

        bytes memory payload = _initPayloadWithDeploy(_deployAuthFor(OWNER));
        vm.expectRevert(IShrincsWallet.InvalidDeployAuthorization.selector);
        realFactory.deployLatestWalletProxy(VAULT_ID, mainCommitment, payable(OWNER), payload);
    }

    function test_setDeployConfig_revertsWhen_indexOutOfRange() public {
        vm.startPrank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(IWalletFactory.InvalidDeployChainIndex.selector, uint16(0)));
        realFactory.setDeployConfig(0, IWalletFactory.DeployMode.Stateful);
        vm.expectRevert(abi.encodeWithSelector(IWalletFactory.InvalidDeployChainIndex.selector, uint16(33)));
        realFactory.setDeployConfig(33, IWalletFactory.DeployMode.Stateful);
        vm.stopPrank();
    }
}
