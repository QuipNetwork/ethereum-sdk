// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {SPHINCSPlusC256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC256sKeccak.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {IVettingFactory} from "../../script/DeployHelpers.sol";
import {DeployShrincsBase} from "../../script/DeployShrincsBase.sol";
import {DeployFactoryBase} from "../../script/DeployFactoryBase.sol";

/// Public wrapper exposing the internal deploy-base helpers so a `Test` can drive
/// them without inheriting `Script` (avoids the Test/Script diamond). Inherits the
/// Shrincs + factory bases — the same diamond as `02_DeployShrincs.s.sol` — so
/// constants and the `ShrincsVerifier` struct come along.
contract DeployHarness is DeployShrincsBase, DeployFactoryBase {
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
        SHRINCS.PublicKey memory verifierPk,
        uint32 hashSuite
    ) public returns (address) {
        return _deployShrincsPaymaster(
            operator,
            pk,
            ShrincsVerifier({paymasterOwner: owner, publicKey: verifierPk, hashSuite: hashSuite})
        );
    }

    function predictLive(address operator, bytes memory saltPreimage) public pure returns (address) {
        return _predictCreateX(operator, saltPreimage);
    }

    function createx() public pure returns (address) {
        return CREATEX;
    }
}

/// @dev Exercises the live deploy sequence (`01_DeployFactory` → `02_DeployShrincs`)
///      via the shared bases: deploy/vet/address/ordering only. The sunset WOTS+
///      flow (`script/deprecated/`) is frozen and deliberately untested here.
contract DeployScriptsTest is Test {
    uint256 internal constant PK = uint256(keccak256("quip.deploy.test.owner"));
    uint256 internal constant MAX_FEE = 1e16;
    uint32 internal constant VERIFIER_MAX_SIGS = 16;

    // Real verifier bundle (keygen'd in setUp): `initialize` derives the
    // commitment + leaf budget from the presented key material, so a synthetic
    // commitment can no longer initialize the paymaster.
    SHRINCS.PublicKey internal verifierPk;

    // Live-contract salt PREIMAGES (CreateX path), mirroring `DeployConstants`
    // as an INDEPENDENT copy: a typo/drift there fails the address asserts
    // below. The factory-proxy preimage doubles as the derivation
    // `02_DeployShrincs` uses to locate the factory.
    bytes internal constant FACTORY_PROXY_PREIMAGE = "QUIP:WalletFactory:Proxy:V1.0.0-beta";
    bytes internal constant SHRINCS_PM_PROXY_PREIMAGE = "QUIP:ShrincsPaymaster:Proxy:V1.1";

    address internal owner; // doubles as the DEPLOY_OPERATOR (sender-guarded salts)
    DeployHarness internal h;

    function setUp() public {
        owner = vm.addr(PK);
        vm.deal(owner, 100 ether);
        h = new DeployHarness();

        bool keygenOk;
        (, verifierPk, keygenOk) = SHRINCSTestSigner.keygen("quip.deploy.test.verifier", VERIFIER_MAX_SIGS);
        require(keygenOk, "verifier keygen failed");

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
        vm.etch(0x9154dA0BA19600C543a8c5ed1B1c44af415B5688, address(new SHRINCS256sKeccak()).code);
        vm.etch(0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A, address(new SPHINCSPlusC256sKeccak()).code);
    }

    /// Independent mirror of the sender-guarded derivation (CreateX MsgSender+False
    /// branch): rawSalt = operator(20) ‖ 0x00 ‖ keccak(preimage)[0:11];
    /// guardedSalt = keccak(bytes32(operator) ‖ rawSalt); CREATE3 from CreateX.
    function _predictLiveIndependent(bytes memory preimage) internal view returns (address) {
        bytes32 raw = bytes32(uint256(uint160(owner)) << 96) | (keccak256(preimage) >> 168);
        bytes32 guarded = keccak256(abi.encodePacked(bytes32(uint256(uint160(owner))), raw));
        return CREATE3.predictDeterministicAddress(guarded, h.createx());
    }

    /// The live sequence (01 factory → 02 shrincs impl + paymaster): every
    /// contract lands at its predicted sender-guarded CreateX address
    /// (independently recomputed here, pinning our helper's formula against
    /// CreateX's internal `_guard`), the Shrincs impl vets, and — with WOTS+
    /// sunset — the Shrincs impl IS `latestWalletImpl`.
    function test_deploySequence_predictedAddresses_shrincsVettedAndLatest() public {
        address fAddr = h.factory(owner, PK, owner, MAX_FEE);
        address sImpl = h.shrincsImpl(owner, PK, fAddr);
        address sPm =
            h.shrincsPaymaster(owner, PK, owner, verifierPk, HashSuite.HASH_SUITE_ID);

        // Sender-guarded CreateX CREATE3, formula pinned by the independent
        // recomputation AND by the helper's own prediction. The factory-proxy
        // assert also pins the derivation `02_DeployShrincs` uses to locate
        // the factory without a FACTORY_ADDRESS env var.
        assertEq(fAddr, _predictLiveIndependent(FACTORY_PROXY_PREIMAGE), "WalletFactory proxy addr");
        assertEq(fAddr, h.predictLive(owner, FACTORY_PROXY_PREIMAGE), "helper prediction agrees");
        assertEq(sPm, _predictLiveIndependent(SHRINCS_PM_PROXY_PREIMAGE), "ShrincsPaymaster proxy addr");

        IVettingFactory f = IVettingFactory(fAddr);
        assertTrue(f.getVettedCodeIndex(sImpl.codehash) != type(uint256).max, "shrincs vetted");

        // WOTS+ is sunset: the freshly vetted Shrincs impl is the
        // `deployLatestWalletProxy` default.
        assertEq(f.latestWalletImpl(), sImpl, "latest must be Shrincs");

        assertGt(sPm.code.length, 0, "shrincs paymaster code");
    }

    /// Re-running every step is a no-op (skip-if-deployed / skip-if-vetted), never
    /// reverting `AlreadyVetted` or a CREATE3 collision.
    function test_idempotent_reRunIsNoOp() public {
        address fAddr = h.factory(owner, PK, owner, MAX_FEE);
        address sImpl1 = h.shrincsImpl(owner, PK, fAddr);
        address sPm1 =
            h.shrincsPaymaster(owner, PK, owner, verifierPk, HashSuite.HASH_SUITE_ID);

        // Second pass — identical addresses, no revert.
        address fAddr2 = h.factory(owner, PK, owner, MAX_FEE);
        address sImpl2 = h.shrincsImpl(owner, PK, fAddr);
        address sPm2 =
            h.shrincsPaymaster(owner, PK, owner, verifierPk, HashSuite.HASH_SUITE_ID);

        assertEq(fAddr, fAddr2, "factory stable");
        assertEq(sImpl1, sImpl2, "shrincs impl stable");
        assertEq(sPm1, sPm2, "shrincs paymaster stable");
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
