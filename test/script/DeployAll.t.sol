// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {SPHINCSPlusC256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC256sKeccak.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {Deployer} from "../../contracts/deprecated/Deployer.sol";
import {IVettingFactory} from "../../script/DeployHelpers.sol";
import {DeployWotsBase} from "../../script/deprecated/DeployWotsBase.sol";
import {DeployShrincsBase} from "../../script/DeployShrincsBase.sol";
import {DeployFactoryBase} from "../../script/DeployFactoryBase.sol";

/// Public wrapper exposing the internal deploy-base helpers so a `Test` can drive
/// them without inheriting `Script` (avoids the Test/Script diamond). Inherits both
/// families + the factory base; constants + the `ShrincsVerifier` struct come along.
/// Live contracts flow through CreateX (sender-guarded); the sunset WOTS+ family
/// through the deprecated Deployer — mirroring `DeployAll.s.sol` exactly.
contract DeployHarness is DeployWotsBase, DeployShrincsBase, DeployFactoryBase {
    function wotsLib(Deployer d, uint256 pk) public returns (address) {
        return _deployWotsPlusLib(d, pk);
    }

    function factory(address operator, uint256 pk, address owner, uint256 maxFee) public returns (address) {
        return _deployFactoryViaCreateX(operator, pk, owner, maxFee);
    }

    function shrincsImpl(address operator, uint256 pk, address f) public returns (address) {
        return _deployShrincsImplAndVet(operator, pk, f);
    }

    function shrincsPaymaster(
        address operator,
        uint256 pk,
        address owner,
        bytes32 commitment,
        uint32 hashSuite,
        uint32 maxSig
    ) public returns (address) {
        return _deployShrincsPaymaster(
            operator,
            pk,
            ShrincsVerifier({paymasterOwner: owner, commitment: commitment, hashSuite: hashSuite, maxSignatures: maxSig})
        );
    }

    function wotsImpl(Deployer d, uint256 pk, address f) public returns (address) {
        return _deployWotsImplAndVet(d, pk, f);
    }

    function quipPaymaster(Deployer d, uint256 pk, address owner) public returns (address) {
        return _deployQuipPaymaster(d, pk, owner);
    }

    function predictLive(address operator, bytes memory saltPreimage) public pure returns (address) {
        return _predictCreateX(operator, saltPreimage);
    }

    function createx() public pure returns (address) {
        return CREATEX;
    }
}

/// @dev Run under the DEFAULT profile: a fresh local Deployer lands WOTSPlus at a
///      non-canonical address, so the `[profile.deploy]` hardcoded link would not
///      match. These tests exercise only deploy/vet/address/ordering — none of
///      which call into the WOTSPlus library — so unlinked WOTS bytecode is fine.
contract DeployAllTest is Test {
    uint256 internal constant PK = uint256(keccak256("quip.deploy.test.owner"));
    uint256 internal constant MAX_FEE = 1e16;
    bytes32 internal constant VERIFIER_COMMITMENT = keccak256("shrincs.verifier.commitment");
    uint32 internal constant VERIFIER_MAX_SIGS = 16;

    // Salts mirror the deploy bases + PredictAddresses (independent copy: a typo
    // here fails the address asserts, catching salt drift).
    bytes32 internal constant WOTSPLUS_SALT = keccak256("QUIP:WOTSPlus:V1.1");
    bytes32 internal constant WOTS_IMPL_SALT = keccak256("QUIP:WOTSPlusImplementation:V1.1");
    bytes32 internal constant QUIP_PAYMASTER_PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1.1");

    // Live-contract salt PREIMAGES (CreateX path). Impl salts bind the verifier
    // scheme tag (PROFILE_TAG = the profile-name hash), spelled out literally per
    // the independent-copy rule above.
    bytes internal constant FACTORY_PROXY_PREIMAGE = "QUIP:WalletFactory:Proxy:V1.0.0-beta";
    bytes internal constant SHRINCS_PM_PROXY_PREIMAGE = "QUIP:ShrincsPaymaster:Proxy:V1.1";

    address internal owner; // doubles as the DEPLOY_OPERATOR (sender-guarded salts)
    Deployer internal deployer;
    DeployHarness internal h;

    function setUp() public {
        owner = vm.addr(PK);
        vm.deal(owner, 100 ether);
        deployer = new Deployer();
        h = new DeployHarness();

        // Provision CreateX at its canonical address. A plain runtime etch is NOT
        // enough: CreateX bakes `_SELF = address(this)` into an immutable at
        // construction and derives return addresses from it, so the constructor
        // must execute WITH the canonical address as `address(this)` — etch the
        // creation code, run it, etch the returned runtime. The creation bytecode
        // comes from the dependency's shipped artifact (CreateX pins solc 0.8.23,
        // so its SOURCE cannot join this 0.8.33 compilation unit).
        address createxAddr = h.createx();
        bytes memory creation =
            vm.getCode("dependencies/pcaversaccio-createx-1.0.0/artifacts/src/CreateX.sol/CreateX.json");
        vm.etch(createxAddr, creation);
        (bool ok, bytes memory runtime) = createxAddr.call("");
        require(ok, "CreateX constructor-at-address failed");
        vm.etch(createxAddr, runtime);

        // Real-chain precondition mirrored locally: the deploy base's
        // `_requireExists` gate expects the canonical hashsigs-solidity CREATE3
        // deploys (sibling + SHRINCS verifier) to already exist.
        vm.etch(0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A, address(new SHRINCS256sKeccak()).code);
        vm.etch(0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A, address(new SPHINCSPlusC256sKeccak()).code);
    }

    function _predictWots(bytes32 salt) internal view returns (address) {
        return CREATE3.predictDeterministicAddress(salt, address(deployer));
    }

    /// Independent mirror of the sender-guarded derivation (CreateX MsgSender+False
    /// branch): rawSalt = operator(20) ‖ 0x00 ‖ keccak(preimage)[0:11];
    /// guardedSalt = keccak(bytes32(operator) ‖ rawSalt); CREATE3 from CreateX.
    function _predictLiveIndependent(bytes memory preimage) internal view returns (address) {
        bytes32 raw = bytes32(uint256(uint160(owner)) << 96) | (keccak256(preimage) >> 168);
        bytes32 guarded = keccak256(abi.encodePacked(bytes32(uint256(uint160(owner))), raw));
        return CREATE3.predictDeterministicAddress(guarded, h.createx());
    }

    /// DeployAll's ordering: factory (CreateX), Shrincs (CreateX, vetted first),
    /// WOTS+ (Deployer, vetted last). Asserts every contract lands at its
    /// predicted address — live ones under the sender-guarded CreateX derivation
    /// (independently recomputed here, pinning our helper's formula against
    /// CreateX's internal `_guard`), WOTS+ ones under the Deployer derivation —
    /// both impls vet, and WOTS+ is `latest`.
    function test_deployAll_predictedAddresses_bothVetted_wotsLatest() public {
        address fAddr = h.factory(owner, PK, owner, MAX_FEE);
        address sImpl = h.shrincsImpl(owner, PK, fAddr);
        address sPm =
            h.shrincsPaymaster(owner, PK, owner, VERIFIER_COMMITMENT, HashSuite.HASH_SUITE_ID, VERIFIER_MAX_SIGS);
        address lib = h.wotsLib(deployer, PK);
        address wImpl = h.wotsImpl(deployer, PK, fAddr);
        address qPm = h.quipPaymaster(deployer, PK, owner);

        // Live contracts: sender-guarded CreateX CREATE3, formula pinned by the
        // independent recomputation AND by the helper's own prediction.
        assertEq(fAddr, _predictLiveIndependent(FACTORY_PROXY_PREIMAGE), "WalletFactory proxy addr");
        assertEq(fAddr, h.predictLive(owner, FACTORY_PROXY_PREIMAGE), "helper prediction agrees");
        assertEq(sPm, _predictLiveIndependent(SHRINCS_PM_PROXY_PREIMAGE), "ShrincsPaymaster proxy addr");

        // Sunset WOTS+ era: Deployer-derived CREATE3.
        assertEq(lib, _predictWots(WOTSPLUS_SALT), "WOTSPlus addr");
        assertEq(wImpl, _predictWots(WOTS_IMPL_SALT), "WOTSPlusImplementation addr");
        assertEq(qPm, _predictWots(QUIP_PAYMASTER_PROXY_SALT), "QuipPaymaster proxy addr");

        IVettingFactory f = IVettingFactory(fAddr);
        assertTrue(f.getVettedCodeIndex(sImpl.codehash) != type(uint256).max, "shrincs vetted");
        assertTrue(f.getVettedCodeIndex(wImpl.codehash) != type(uint256).max, "wots vetted");

        // WOTS+ vetted LAST -> it is the default `deployLatestWalletProxy` target.
        assertEq(f.latestWalletImpl(), wImpl, "latest must be WOTS+");

        assertGt(sPm.code.length, 0, "shrincs paymaster code");
        assertGt(qPm.code.length, 0, "quip paymaster code");
    }

    /// Standalone Shrincs (vetted after WOTS+) makes Shrincs `latest` — the
    /// documented side effect of `DeployAllShrincs`.
    function test_standaloneShrincs_makesShrincsLatest() public {
        address fAddr = h.factory(owner, PK, owner, MAX_FEE);
        h.wotsLib(deployer, PK);
        h.wotsImpl(deployer, PK, fAddr); // WOTS+ vetted first -> latest
        address sImpl = h.shrincsImpl(owner, PK, fAddr); // Shrincs vetted last -> latest
        assertEq(IVettingFactory(fAddr).latestWalletImpl(), sImpl, "shrincs latest after standalone");
    }

    /// Re-running every step is a no-op (skip-if-deployed / skip-if-vetted), never
    /// reverting `AlreadyVetted` or a CREATE3 collision.
    function test_idempotent_reRunIsNoOp() public {
        address fAddr = h.factory(owner, PK, owner, MAX_FEE);
        address sImpl1 = h.shrincsImpl(owner, PK, fAddr);
        h.wotsLib(deployer, PK);
        address wImpl1 = h.wotsImpl(deployer, PK, fAddr);

        // Second pass — identical addresses, no revert.
        address fAddr2 = h.factory(owner, PK, owner, MAX_FEE);
        address sImpl2 = h.shrincsImpl(owner, PK, fAddr);
        h.wotsLib(deployer, PK);
        address wImpl2 = h.wotsImpl(deployer, PK, fAddr);

        assertEq(fAddr, fAddr2, "factory stable");
        assertEq(sImpl1, sImpl2, "shrincs impl stable");
        assertEq(wImpl1, wImpl2, "wots impl stable");
    }

    /// Squat-proofing: a caller whose address does not match the salt's first 20
    /// bytes cannot consume the operator's salt — the deploy helper refuses
    /// before broadcast, and CreateX itself would revert `InvalidSalt`.
    function test_senderGuard_nonOperatorCannotConsumeSalt() public {
        uint256 strangerPk = uint256(keccak256("quip.deploy.test.stranger"));
        vm.deal(vm.addr(strangerPk), 10 ether);
        vm.expectRevert(bytes("WalletFactory impl: broadcaster is not DEPLOY_OPERATOR"));
        h.factory(owner, strangerPk, owner, MAX_FEE);
    }
}
