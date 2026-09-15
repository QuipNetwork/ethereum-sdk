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
    bytes internal constant FACTORY_IMPL_PREIMAGE = "QUIP:WalletFactory:Impl:V1.0.1-beta.1";
    bytes internal constant FACTORY_PROXY_PREIMAGE = "QUIP:WalletFactory:Proxy:V1.0.1";
    bytes internal constant SHRINCS_PM_PROXY_PREIMAGE = "QUIP:ShrincsPaymaster:Proxy:V1.0.1";

    // The two IMPLEMENTATION preimages bind the verifier scheme tag. Spelled out
    // from the profile STRING rather than importing `SHRINCSParams.PROFILE_ID`,
    // so this stays an independent copy end to end.
    bytes32 internal constant PROFILE_ID_INDEPENDENT = keccak256("shrincs-256s-keccak");

    // The published registry (`DEPLOYMENTS.md`, `src/v1/shrincs/addresses.ts`) —
    // independent literals, including the operator they derive from. Anything that
    // moves an address (salt text, operator, guard formula, CREATE3 math) breaks
    // `test_publishedRegistry_matchesDerivation`.
    address internal constant CANONICAL_OPERATOR_PUBLISHED = 0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26;
    address internal constant PUBLISHED_FACTORY_IMPL = 0x77622e199DfF602f937fC5E5eB6479aE4b18161F;
    address internal constant PUBLISHED_FACTORY_PROXY = 0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8;
    address internal constant PUBLISHED_SHRINCS_WALLET = 0x680840c831c6D147404a0e00edA08a5360564FBC;
    address internal constant PUBLISHED_SHRINCS_PM_IMPL = 0x5E4E4003118a0F8825494D76E86Db2ed654992d2;
    address internal constant PUBLISHED_SHRINCS_PM_PROXY = 0x430c8c89492E3541e141148Dd7a7D6dD432e5890;

    // eip1967.proxy.implementation slot (keccak256("eip1967.proxy.implementation") - 1),
    // read to recover an impl address from behind its ERC-1967 proxy.
    bytes32 internal constant ERC1967_IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

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
        vm.etch(0xF2f9E6D692da41b089c3c261c41509669eEc5567, address(new SHRINCS256sKeccak()).code);
        vm.etch(0xe52707C5D76E2F7c3314cF3dcc340eB9BbAE3864, address(new SPHINCSPlusC256sKeccak()).code);
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
        p[2] = abi.encodePacked("QUIP:ShrincsWallet:Impl:V1.0.1-beta.2:", PROFILE_ID_INDEPENDENT);
        p[3] = abi.encodePacked("QUIP:ShrincsPaymaster:Impl:V1.0.1-beta.2:", PROFILE_ID_INDEPENDENT);
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

        // Pin the three IMPLEMENTATION addresses too, not just the two proxies.
        // Vetting keys on codehash, not address, so a drifted impl salt would
        // deploy at an unpredicted address and still vet — assert the ACTUALLY
        // deployed impl (through real CreateX) equals the prediction. Factory and
        // paymaster impls sit behind their ERC-1967 proxies.
        bytes[5] memory pre = _livePreimages();
        assertEq(sImpl, _predictLiveIndependent(pre[2]), "ShrincsWallet impl addr");
        assertEq(sImpl, h.predictLive(owner, pre[2]), "helper agrees on wallet impl");
        address fImpl = address(uint160(uint256(vm.load(fAddr, ERC1967_IMPL_SLOT))));
        assertEq(fImpl, _predictLiveIndependent(pre[0]), "WalletFactory impl addr");
        address pmImpl = address(uint160(uint256(vm.load(sPm, ERC1967_IMPL_SLOT))));
        assertEq(pmImpl, _predictLiveIndependent(pre[3]), "ShrincsPaymaster impl addr");
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

    /// In-place generation bump: a chain that already holds the paymaster proxy
    /// delegating to an EARLIER impl gets upgraded to this build's impl (owner
    /// UUPS upgrade, no re-init) instead of failing the identity assert.
    function test_upgradeInPlace_existingPaymasterProxyMovesToThisImpl() public {
        h.factory(owner, PK, owner, MAX_FEE);
        address sPm =
            h.shrincsPaymaster(owner, PK, owner, verifierPk, HashSuite.HASH_SUITE_ID);
        address canonicalImpl = address(uint160(uint256(vm.load(sPm, ERC1967_IMPL_SLOT))));

        // Simulate the previous generation: same code at another address (a
        // UUPS target must be a real UUPS impl for `proxiableUUID`), pointed at
        // by the live proxy.
        address oldImpl = makeAddr("previous-paymaster-impl");
        vm.etch(oldImpl, canonicalImpl.code);
        vm.store(sPm, ERC1967_IMPL_SLOT, bytes32(uint256(uint160(oldImpl))));
        (bytes32 commitmentBefore,,,,) = IShrincsVerifierView(sPm).getShrincsVerifier();

        address sPm2 =
            h.shrincsPaymaster(owner, PK, owner, verifierPk, HashSuite.HASH_SUITE_ID);
        assertEq(sPm2, sPm, "proxy address stable");
        assertEq(
            address(uint160(uint256(vm.load(sPm, ERC1967_IMPL_SLOT)))),
            canonicalImpl,
            "proxy upgraded back to this build's impl"
        );
        (bytes32 commitmentAfter,,,,) = IShrincsVerifierView(sPm).getShrincsVerifier();
        assertEq(commitmentAfter, commitmentBefore, "state preserved across the upgrade");
    }

    /// The upgrade is `onlyOwner`: a proxy owned by someone else refuses before
    /// any broadcast.
    function test_upgradeInPlace_revertsWhen_keyIsNotProxyOwner() public {
        h.factory(owner, PK, owner, MAX_FEE);
        address other = makeAddr("other-paymaster-owner");
        address sPm =
            h.shrincsPaymaster(owner, PK, other, verifierPk, HashSuite.HASH_SUITE_ID);
        address canonicalImpl = address(uint160(uint256(vm.load(sPm, ERC1967_IMPL_SLOT))));
        address oldImpl = makeAddr("previous-paymaster-impl");
        vm.etch(oldImpl, canonicalImpl.code);
        vm.store(sPm, ERC1967_IMPL_SLOT, bytes32(uint256(uint160(oldImpl))));

        vm.expectRevert(
            bytes("ShrincsPaymaster proxy: PRIVATE_KEY is not the proxy owner (upgrade is onlyOwner)")
        );
        h.shrincsPaymaster(owner, PK, other, verifierPk, HashSuite.HASH_SUITE_ID);
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

interface IShrincsVerifierView {
    function getShrincsVerifier() external view returns (bytes32, uint32, uint256, uint32, uint32);
}
