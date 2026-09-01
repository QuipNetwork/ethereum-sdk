// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {SHRINCSStatelessVectorSigner} from
    "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSStatelessVectorSigner.sol";
import {SHRINCSStatelessVectorSigningFacade} from
    "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSStatelessVectorSigningFacade.sol";
import {ShrincsWallet} from "../../contracts/shrincs/ShrincsWallet.sol";
import {ShrincsWalletCodec as Codec} from "../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../contracts/shrincs/interfaces/IShrincsWallet.sol";

/// @dev The live WalletFactory surface this test needs (frozen, deployed).
interface IDeployedFactory {
    function deployLatestWalletProxy(
        bytes32 commitment,
        address payable to,
        bytes calldata payload
    ) external payable returns (address);

    function vetImplementation(address impl) external;

    function creationFee() external view returns (uint256);

    function latestWalletImpl() external view returns (address);

    function owner() external view returns (address);
}

/// @dev The DEPLOYED ShrincsWallet implementation surface this test needs. Declared locally
///      (not via the repo interface) so the test binds the frozen on-chain ABI, immune to
///      interface drift in the working tree.
interface IDeployedWallet {
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;

    function actionNonce() external view returns (uint256);

    function keyVersion() external view returns (uint256);

    function getShrincsPublicKeyCommitment() external view returns (bytes32);

    function getShrincsVerifier() external view returns (address);

    function owner() external view returns (address);
}

/// @title Fork tests: the upgrade boundary between the DEPLOYED implementation and this tree's
/// @dev Forks Base mainnet and deploys a wallet through the LIVE factory, so it runs the live,
///      frozen `V1.0.1-beta.2` implementation bytecode (old 6-word init format, whole-blob
///      `verifyUpgrade` forward, tstore migrate guard). Four explicit cases:
///
///        FORWARD (deployed → new), both proven to SUCCEED:
///        1. with migration    — old caller's tstore guard ignored, new `migrate`'s ERC-1967
///                               gate passes mid-upgrade, fresh bundles installed, epoch bump;
///        2. without migration — pointer swap only, state carried as-is (pre-isolation
///                               ERC-1271 semantics remain until a later migrate).
///
///        BACKWARD (new → deployed), both proven to REVERT — the boundary is forward-only:
///        3. with migration;
///        4. without migration.
///        Both die at the PROBE: the deployed `verifyUpgrade` is not context-free — probed
///        directly on the bare implementation it verifies against its own EMPTY storage
///        (commitment 0x0), which no real bundle can match. The tests present the BEST-EFFORT
///        forgery (the exact message the bare implementation checks, signed with a real key)
///        and it still fails — unforgeable, not merely malformed.
contract ShrincsForkUpgradeFromDeployed is Test {
    string internal constant BASE_RPC_ENV = "API_URL_BASE";

    /// @dev Live WalletFactory proxy (`src/v1/addresses.json`; CreateX-deterministic, identical
    ///      on Base mainnet + testnets).
    address internal constant FACTORY = 0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8;

    // ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    uint32 internal constant SIGN_BASE = 32;
    uint32 internal constant MAX_SIG = SIGN_BASE + 8;

    IDeployedFactory internal factory = IDeployedFactory(FACTORY);
    IDeployedWallet internal wallet;
    address internal deployedImpl;
    ShrincsWallet internal newImpl;
    SHRINCSStatelessVectorSigner internal statelessSigner;

    SHRINCS.SigningKey internal mainKey;
    SHRINCS.PublicKey internal mainPk;
    bytes32 internal mainCommitment;
    bytes32 internal erc1271Commitment;

    // Post-migration key material (populated by `_migrateWalletToNewImpl`).
    SHRINCS.SigningKey internal freshKey;
    SHRINCS.PublicKey internal freshPk;
    bytes32 internal freshCommitment;
    SHRINCS.PublicKey internal freshErc1271Pk;

    address internal OWNER;

    function setUp() public {
        vm.createSelectFork(vm.envString(BASE_RPC_ENV));
        OWNER = makeAddr("fork-upgrade-owner");
        vm.deal(OWNER, 10 ether);
        statelessSigner = new SHRINCSStatelessVectorSigner();

        bool ok;
        (mainKey, mainPk, ok) = SHRINCSTestSigner.keygen("fork-upgrade-main-key", MAX_SIG);
        assertTrue(ok, "main keygen");
        mainCommitment = _commitment32(mainPk);
        // The deployed init format records the ERC-1271 verifier as a bare commitment
        // (pre-isolation semantics); this test never signs with it.
        (, SHRINCS.PublicKey memory oldErc1271Pk, bool ok2) =
            SHRINCSTestSigner.keygen("fork-upgrade-old-erc1271", MAX_SIG);
        assertTrue(ok2, "old erc1271 keygen");
        erc1271Commitment = _commitment32(oldErc1271Pk);

        // ── 1. Deploy a wallet through the LIVE factory: it runs the DEPLOYED implementation ──
        deployedImpl = factory.latestWalletImpl();
        assertTrue(deployedImpl != address(0), "live latestWalletImpl");
        // DEPLOYED 6-word init format: (commitment, pkSeed, mainBundle, hashSuite,
        // erc1271Commitment, erc1271HashSuite) — erc1271 is a bytes32, not a bundle.
        bytes memory initPayload = abi.encode(
            mainCommitment,
            _toBytes32(mainPk.pkSeed),
            mainPk,
            HashSuite.HASH_SUITE_ID,
            erc1271Commitment,
            HashSuite.HASH_SUITE_ID
        );
        // CREATE3 salt / factory identity: v1Commitment(mainC, erc1271C, owner) — the deployed
        // `initialize` recomputes and checks it (formula unchanged across versions).
        bytes32 identity = Codec.v1Commitment(mainCommitment, erc1271Commitment, OWNER);
        uint256 fee = factory.creationFee();
        vm.prank(OWNER);
        address walletAddr =
            factory.deployLatestWalletProxy{value: fee + 1 ether}(identity, payable(OWNER), initPayload);
        wallet = IDeployedWallet(walletAddr);
        assertEq(wallet.owner(), OWNER, "live deploy installed the owner");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment, "live deploy installed the main key");
        assertEq(_installedImpl(), deployedImpl, "wallet proxy points at the deployed implementation");

        // ── 2. Deploy the NEW implementation from this tree, against the LIVE pinned verifier ──
        newImpl = new ShrincsWallet(payable(FACTORY), wallet.getShrincsVerifier());

        // ── 3. Vet it as the live factory owner ──
        vm.prank(factory.owner());
        factory.vetImplementation(address(newImpl));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              FORWARD: deployed → new                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Case 1 — forward WITH migration: old bytecode authorizes, probes (whole-blob
    ///      forward into the `word[0] == 0xc0` branch), migrates (ERC-1967 gate), swaps.
    function test_forkUpgrade_withMigration_succeeds() public {
        bytes memory migrator = _freshMigrator();
        SHRINCS.Signature memory sig =
            _signUpgradeAuth(mainKey, mainPk, mainCommitment, address(newImpl), true, migrator);
        bytes memory blob =
            abi.encode(mainPk, sig, true, migrator, wallet.actionNonce(), _probeVector(address(newImpl)));

        // The SDK's pre-flight: STATICCALL the new impl's probe with the FULL blob (exactly what
        // the deployed caller will forward) — the `word[0] == 0xc0` branch must accept it.
        (bool preflight,) = address(newImpl).staticcall(
            abi.encodeCall(IShrincsWallet.verifyUpgrade, (address(newImpl), blob))
        );
        assertTrue(preflight, "verifyUpgrade pre-flight accepts the full auth blob");

        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(newImpl), blob);

        assertEq(_installedImpl(), address(newImpl), "ERC-1967 pointer swapped to the new implementation");
        assertEq(wallet.keyVersion(), 1, "migrate ran and bumped the key epoch");
        assertEq(wallet.getShrincsPublicKeyCommitment(), freshCommitment, "migrate installed the fresh main key");
        // A view only the NEW code answers with full-bundle semantics.
        assertEq(
            IShrincsWallet(address(wallet)).getErc1271PublicKeyCommitment(),
            _commitment32(freshErc1271Pk),
            "migrate installed the fresh ERC-1271 bundle"
        );
    }

    /// @dev Case 2 — forward WITHOUT migration: pointer swap only. The wallet keeps its keys,
    ///      epoch, and pre-isolation ERC-1271 state (a later migrate can modernize them).
    function test_forkUpgrade_withoutMigration_succeeds() public {
        SHRINCS.Signature memory sig =
            _signUpgradeAuth(mainKey, mainPk, mainCommitment, address(newImpl), false, bytes(""));
        bytes memory blob =
            abi.encode(mainPk, sig, false, bytes(""), wallet.actionNonce(), _probeVector(address(newImpl)));

        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(newImpl), blob);

        assertEq(_installedImpl(), address(newImpl), "ERC-1967 pointer swapped to the new implementation");
        assertEq(wallet.keyVersion(), 0, "no migrate: epoch unchanged");
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment, "no migrate: main key carried as-is");
        assertEq(wallet.actionNonce(), 1, "consumed upgrade signature advanced the action nonce");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*             BACKWARD: new → deployed                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Case 3 — backward WITH migration: reverts. The new caller STATICCALLs the deployed
    ///      `verifyUpgrade` ON THE BARE OLD IMPLEMENTATION, which verifies against its own empty
    ///      storage (commitment 0x0) — even the best-effort forged probe fails. (Were the probe
    ///      ever passed, the old `migrate`'s tstore gate — which the new caller never sets —
    ///      would refuse next.)
    function test_forkDowngrade_withMigration_reverts() public {
        _migrateWalletToNewImpl();

        // Content unreachable — the probe blocks first; only its hash is signed.
        bytes memory migrator = hex"deadbeef";
        SHRINCS.Signature memory sig =
            _signUpgradeAuth(freshKey, freshPk, freshCommitment, deployedImpl, true, migrator);
        bytes memory blob =
            abi.encode(freshPk, sig, true, migrator, wallet.actionNonce(), _bestEffortOldProbe());

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(deployedImpl, blob);

        assertEq(_installedImpl(), address(newImpl), "pointer unchanged: still the new implementation");
    }

    /// @dev Case 4 — backward WITHOUT migration: reverts identically. The probe is the first
    ///      gate and it is unforgeable regardless of the migrate flag.
    function test_forkDowngrade_withoutMigration_reverts() public {
        _migrateWalletToNewImpl();

        SHRINCS.Signature memory sig =
            _signUpgradeAuth(freshKey, freshPk, freshCommitment, deployedImpl, false, bytes(""));
        bytes memory blob =
            abi.encode(freshPk, sig, false, bytes(""), wallet.actionNonce(), _bestEffortOldProbe());

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.upgradeToAndCall(deployedImpl, blob);

        assertEq(_installedImpl(), address(newImpl), "pointer unchanged: still the new implementation");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPERS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Drives the proven forward path (case 1's mechanics) so the backward tests start
    ///      from a wallet running the NEW implementation on fresh key material.
    function _migrateWalletToNewImpl() internal {
        bytes memory migrator = _freshMigrator();
        SHRINCS.Signature memory sig =
            _signUpgradeAuth(mainKey, mainPk, mainCommitment, address(newImpl), true, migrator);
        bytes memory blob =
            abi.encode(mainPk, sig, true, migrator, wallet.actionNonce(), _probeVector(address(newImpl)));
        vm.prank(OWNER);
        wallet.upgradeToAndCall(address(newImpl), blob);
        assertEq(_installedImpl(), address(newImpl), "precondition: wallet on the new implementation");
        assertEq(wallet.keyVersion(), 1, "precondition: migrated to epoch 1");
    }

    /// @dev NEW-format init payload with entirely fresh bundles (the new `migrate` refuses any
    ///      tree the wallet has already spent). Stores the fresh key material for later signing.
    function _freshMigrator() internal returns (bytes memory) {
        bool ok;
        (freshKey, freshPk, ok) = SHRINCSTestSigner.keygen("fork-upgrade-fresh-main", MAX_SIG);
        assertTrue(ok, "fresh main keygen");
        freshCommitment = _commitment32(freshPk);
        bool ok2;
        (, freshErc1271Pk, ok2) = SHRINCSTestSigner.keygen("fork-upgrade-fresh-erc1271", MAX_SIG);
        assertTrue(ok2, "fresh erc1271 keygen");
        return abi.encode(
            freshCommitment,
            _toBytes32(freshPk.pkSeed),
            freshPk,
            HashSuite.HASH_SUITE_ID,
            freshErc1271Pk,
            HashSuite.HASH_SUITE_ID
        );
    }

    /// @dev Stateful upgrade authorization over the wallet's LIVE signing context (identical
    ///      recipe across the deployed and new implementations; leaf `SIGN_BASE + 1` is fresh
    ///      in whichever epoch the wallet is on).
    function _signUpgradeAuth(
        SHRINCS.SigningKey memory key,
        SHRINCS.PublicKey memory, /* pk (bound into the blob by the caller) */
        bytes32 commitment,
        address target,
        bool shouldMigrate,
        bytes memory migrator
    ) internal view returns (SHRINCS.Signature memory sig) {
        bytes32 payloadHash = Codec.upgradePayloadHash(target, shouldMigrate, keccak256(migrator));
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            _walletDomainSeparator(),
            wallet.actionNonce(),
            wallet.keyVersion(),
            Codec.ACTION_UPGRADE,
            payloadHash
        );
        bool ok;
        (sig, ok) = SHRINCSTestSigner.signStatefulRawAtLeaf(
            key,
            SIGN_BASE + 1,
            abi.encodePacked(
                SHRINCS.statefulRawMessageHash(commitment, SHRINCS.statefulActionMessageHash(commitment, ctx))
            )
        );
        require(ok, "upgrade stateful sign failed");
    }

    /// @dev Bare 3-field probe vector for the NEW implementation's `verifyUpgrade`: a throwaway
    ///      bundle signing the recomputed digest of the upgrade target.
    function _probeVector(address target) internal returns (bytes memory) {
        (SHRINCS.SigningKey memory probeKey, SHRINCS.PublicKey memory probePk, bool ok) =
            SHRINCSTestSigner.keygen("fork-upgrade-probe", MAX_SIG);
        assertTrue(ok, "probe keygen");
        bytes32 probeCommitment = _commitment32(probePk);
        bytes32 digest = Codec.probeDigest(target);
        (SHRINCS.Signature memory probeStateful, bool okS) = SHRINCSTestSigner.signStatefulRawAtLeaf(
            probeKey,
            SIGN_BASE + 1,
            abi.encodePacked(SHRINCS.statefulRawMessageHash(probeCommitment, digest))
        );
        assertTrue(okS, "probe stateful sign");
        SPHINCSPlusC.Signature memory probeStateless = _signStatelessRaw(
            probeKey, probePk, abi.encodePacked(SHRINCS.statelessRawMessageHash(probeCommitment, digest))
        );
        return abi.encode(probePk, probeStateful, probeStateless);
    }

    /// @dev BEST-EFFORT forged probe for the DEPLOYED `verifyUpgrade`, probed directly on the
    ///      bare old implementation: a well-formed old-style 5-field auth blob whose signature
    ///      covers the EXACT message the bare implementation rebuilds from its own storage
    ///      (domain over the old impl's address, keyVersion 0, blob-borne nonce 0). It still
    ///      fails, because verification runs against the bare implementation's commitment slot —
    ///      0x0 — which no real bundle's commitment can equal.
    function _bestEffortOldProbe() internal returns (bytes memory) {
        (SHRINCS.SigningKey memory forgeKey, SHRINCS.PublicKey memory forgePk, bool ok) =
            SHRINCSTestSigner.keygen("fork-downgrade-forge", MAX_SIG);
        assertTrue(ok, "forge keygen");
        bytes32 payloadHash = Codec.upgradePayloadHash(deployedImpl, false, keccak256(bytes("")));
        bytes32 bareDomain =
            keccak256(abi.encodePacked(Codec.DOMAIN_TAG, block.chainid, uint256(uint160(deployedImpl))));
        SHRINCS.ActionContext memory ctx =
            Codec.buildActionContext(bareDomain, 0, 0, Codec.ACTION_UPGRADE, payloadHash);
        // The bare implementation's commitment slot is empty: it checks against 0x0.
        bytes32 zeroCommitment = bytes32(0);
        (SHRINCS.Signature memory sig, bool okS) = SHRINCSTestSigner.signStatefulRawAtLeaf(
            forgeKey,
            SIGN_BASE + 1,
            abi.encodePacked(
                SHRINCS.statefulRawMessageHash(
                    zeroCommitment, SHRINCS.statefulActionMessageHash(zeroCommitment, ctx)
                )
            )
        );
        assertTrue(okS, "forge stateful sign");
        return abi.encode(forgePk, sig, false, bytes(""), uint256(0));
    }

    /// @dev The wallet's SHRINCS signing domain (mirrors `_shrincsDomainSeparator`, unchanged
    ///      across versions).
    function _walletDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(Codec.DOMAIN_TAG, block.chainid, uint256(uint160(address(wallet)))));
    }

    function _installedImpl() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(wallet), IMPL_SLOT))));
    }

    function _signStatelessRaw(
        SHRINCS.SigningKey memory key,
        SHRINCS.PublicKey memory pk,
        bytes memory message
    ) internal returns (SPHINCSPlusC.Signature memory sig) {
        (bytes32 sessionId, bool ok) = statelessSigner.beginSession(key, pk, message);
        require(ok, "stateless session begin failed");
        (, sig, ok) = SHRINCSStatelessVectorSigningFacade.completeSession(statelessSigner, sessionId);
        require(ok, "stateless sign failed");
    }

    function _commitment32(SHRINCS.PublicKey memory pk) internal pure returns (bytes32 out) {
        bytes memory c = pk.publicKeyCommitment;
        require(c.length == 32, "commitment not 32 bytes");
        assembly {
            out := mload(add(c, 32))
        }
    }

    function _toBytes32(bytes memory b) internal pure returns (bytes32 out) {
        require(b.length == 32, "not 32 bytes");
        assembly {
            out := mload(add(b, 32))
        }
    }
}
