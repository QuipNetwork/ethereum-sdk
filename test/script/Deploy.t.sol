// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {ICreateX} from "pcaversaccio-createx-1.0.0/src/ICreateX.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {SPHINCSPlusC256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC256sKeccak.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {DeployConstants} from "../../script/Constants.sol";
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
    bytes internal constant FACTORY_IMPL_PREIMAGE = "QUIP:WalletFactory:Impl:V1.0.0-beta";
    bytes internal constant FACTORY_PROXY_PREIMAGE = "QUIP:WalletFactory:Proxy:V1.0.0";
    bytes internal constant SHRINCS_PM_PROXY_PREIMAGE = "QUIP:ShrincsPaymaster:Proxy:V1.0.0";

    // The two IMPLEMENTATION preimages bind the verifier scheme tag. Spelled out
    // from the profile STRING rather than importing `SHRINCSParams.PROFILE_ID`,
    // so this stays an independent copy end to end.
    bytes32 internal constant PROFILE_ID_INDEPENDENT = keccak256("shrincs-256s-keccak");

    // The published registry (`DEPLOYMENTS.md`, `src/v1/shrincs/addresses.ts`) —
    // independent literals, including the operator they derive from. Anything that
    // moves an address (salt text, operator, guard formula, CREATE3 math) breaks
    // `test_publishedRegistry_matchesDerivation`.
    address internal constant CANONICAL_OPERATOR_PUBLISHED = 0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26;
    address internal constant PUBLISHED_FACTORY_IMPL = 0x738456Bc546b887764bD6C462FDA6d49bBcA0c9f;
    address internal constant PUBLISHED_FACTORY_PROXY = 0xdCD90563B912f82D2f23d5c7988B3Fec2da63471;
    address internal constant PUBLISHED_SHRINCS_WALLET = 0x33d3949117c8Bba7A3637C96a564a817E00c5aE0;
    address internal constant PUBLISHED_SHRINCS_PM_IMPL = 0x995bDB6768F25822Faafb2c9b6Ad7Cf10CB6EEc3;
    address internal constant PUBLISHED_SHRINCS_PM_PROXY = 0x077C06913777777DfABf951a5A0F8CA665764ac9;

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
        vm.etch(0xE6F2970bA30d59e8288b7007bA755828372457c3, address(new SHRINCS256sKeccak()).code);
        vm.etch(0x97B3726F44e3B7521199CE4e0fC160A32A597d31, address(new SPHINCSPlusC256sKeccak()).code);
    }

    /// Independent mirror of the raw-salt layout: operator(20) ‖ 0x00 ‖
    /// keccak(preimage)[0:11]. Byte 20 is left unwritten here ON PURPOSE — this is
    /// the mirror, so it must reproduce the layout from the spec rather than from
    /// `CreateXHelpers`' constants.
    function _rawSaltIndependent(address op, bytes memory preimage) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(op)) << 96) | (keccak256(preimage) >> 168);
    }

    /// Independent mirror of the sender-guarded derivation (CreateX MsgSender+False
    /// branch): guardedSalt = keccak(bytes32(operator) ‖ rawSalt); CREATE3 from CreateX.
    function _predictIndependent(address op, bytes memory preimage) internal view returns (address) {
        bytes32 guarded =
            keccak256(abi.encodePacked(bytes32(uint256(uint160(op))), _rawSaltIndependent(op, preimage)));
        return CREATE3.predictDeterministicAddress(guarded, h.createx());
    }

    /// The address the SAME salt resolves to on CreateX's PERMISSIONLESS branch
    /// (`guardedSalt = keccak256(abi.encode(salt))`) — where a non-operator caller
    /// lands. Must never coincide with the permissioned address.
    function _predictPermissionless(address op, bytes memory preimage) internal view returns (address) {
        return CREATE3.predictDeterministicAddress(
            keccak256(abi.encode(_rawSaltIndependent(op, preimage))), h.createx()
        );
    }

    function _predictLiveIndependent(bytes memory preimage) internal view returns (address) {
        return _predictIndependent(owner, preimage);
    }

    /// Every live preimage, in registry order.
    function _livePreimages() internal pure returns (bytes[5] memory p) {
        p[0] = FACTORY_IMPL_PREIMAGE;
        p[1] = FACTORY_PROXY_PREIMAGE;
        p[2] = abi.encodePacked("QUIP:ShrincsWallet:Impl:V1.0.0-beta:", PROFILE_ID_INDEPENDENT);
        p[3] = abi.encodePacked("QUIP:ShrincsPaymaster:Impl:V1.0.0-beta:", PROFILE_ID_INDEPENDENT);
        p[4] = SHRINCS_PM_PROXY_PREIMAGE;
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

    /// Squat-proofing, first line: the deploy helper refuses before broadcast when
    /// the broadcaster is not the operator.
    function test_senderGuard_nonOperatorCannotConsumeSalt() public {
        uint256 strangerPk = uint256(keccak256("quip.deploy.test.stranger"));
        vm.deal(vm.addr(strangerPk), 10 ether);
        vm.expectRevert(bytes("WalletFactory impl: broadcaster is not DEPLOY_OPERATOR"));
        h.factory(owner, strangerPk, owner, MAX_FEE);
    }

    /// Squat-proofing, the part that actually matters: what REAL CreateX does when
    /// a stranger presents the operator's salt, executed against the etched
    /// singleton instead of asserted in prose.
    ///
    /// It does NOT revert. `_parseSalt` sees leading bytes that are neither
    /// `msg.sender` nor `address(0)`, so it falls through to the PERMISSIONLESS
    /// branch (`guardedSalt = keccak256(abi.encode(salt))`) and deploys
    /// successfully — somewhere else. The canonical address is untouched, which is
    /// the squat-proofing; the silence is why the helper checks the broadcaster
    /// first (a wrong caller is otherwise indistinguishable from a good one).
    function test_senderGuard_strangerLandsElsewhere_canonicalUntouched() public {
        address stranger = vm.addr(uint256(keccak256("quip.deploy.test.stranger")));
        vm.deal(stranger, 10 ether);

        bytes32 operatorSalt = _rawSaltIndependent(owner, FACTORY_PROXY_PREIMAGE);
        address canonical = _predictIndependent(owner, FACTORY_PROXY_PREIMAGE);
        assertEq(canonical.code.length, 0, "precondition: canonical address is empty");

        vm.prank(stranger);
        address landed = ICreateX(h.createx()).deployCreate3(operatorSalt, type(Tiny).creationCode);

        assertTrue(landed != canonical, "stranger must never reach the canonical address");
        assertEq(
            landed,
            _predictPermissionless(owner, FACTORY_PROXY_PREIMAGE),
            "stranger lands on the permissionless branch"
        );
        assertEq(canonical.code.length, 0, "canonical address must remain unoccupied");

        // And the operator can still take its own address afterwards — the salt
        // was not burned by the stranger's deploy.
        assertEq(h.factory(owner, PK, owner, MAX_FEE), canonical, "operator still reaches canonical");
    }

    /// The docs↔code lock. Re-derives every published address from the published
    /// operator and the salt STRINGS, and pins the operator constant itself. A
    /// changed salt, a changed operator, or drift in the guard/CREATE3 math all
    /// land here — before they land on a chain.
    function test_publishedRegistry_matchesDerivation() public view {
        assertEq(
            DeployConstants.CANONICAL_OPERATOR,
            CANONICAL_OPERATOR_PUBLISHED,
            "CANONICAL_OPERATOR drifted from the published registry"
        );

        address op = CANONICAL_OPERATOR_PUBLISHED;
        bytes[5] memory preimages = _livePreimages();
        address[5] memory published = [
            PUBLISHED_FACTORY_IMPL,
            PUBLISHED_FACTORY_PROXY,
            PUBLISHED_SHRINCS_WALLET,
            PUBLISHED_SHRINCS_PM_IMPL,
            PUBLISHED_SHRINCS_PM_PROXY
        ];

        for (uint256 i = 0; i < 5; ++i) {
            // Independent mirror and the production helper must BOTH land on the
            // published address.
            assertEq(_predictIndependent(op, preimages[i]), published[i], "published address drifted");
            assertEq(h.predictLive(op, preimages[i]), published[i], "helper disagrees with the registry");
        }
    }

    /// The squat surface is closed for every salt: the permissioned address a
    /// canonical deploy reaches is never the permissionless address a stranger
    /// reaches, and no two canonical addresses collide.
    function test_saltInvariants_permissionedDistinctFromPermissionless() public view {
        address op = CANONICAL_OPERATOR_PUBLISHED;
        bytes[5] memory preimages = _livePreimages();
        address[5] memory permissioned;

        for (uint256 i = 0; i < 5; ++i) {
            permissioned[i] = _predictIndependent(op, preimages[i]);
            assertTrue(
                permissioned[i] != _predictPermissionless(op, preimages[i]),
                "permissioned and permissionless addresses must differ"
            );
            // Layout: operator in bytes 0-19, cross-chain flag OFF in byte 20.
            bytes32 raw = _rawSaltIndependent(op, preimages[i]);
            assertEq(address(uint160(uint256(raw >> 96))), op, "salt bytes 0-19 must be the operator");
            assertEq(uint8(uint256(raw >> 88)), 0x00, "salt byte 20 must be 0x00 (chain-invariant)");
        }

        for (uint256 i = 0; i < 5; ++i) {
            for (uint256 j = i + 1; j < 5; ++j) {
                assertTrue(permissioned[i] != permissioned[j], "canonical addresses must be distinct");
            }
        }
    }
}

/// Minimal deployable payload for the stranger-squat test — the point is which
/// ADDRESS the deploy reaches, not what lands there.
contract Tiny {
    uint256 public x = 1;
}
