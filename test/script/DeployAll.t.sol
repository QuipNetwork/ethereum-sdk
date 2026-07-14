// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCS256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS256sKeccak.sol";
import {SPHINCSPlusC256sKeccak} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC256sKeccak.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {Deployer} from "../../contracts/Deployer.sol";
import {IVettingFactory} from "../../script/DeployHelpers.sol";
import {DeployWotsBase} from "../../script/DeployWotsBase.sol";
import {DeployShrincsBase} from "../../script/DeployShrincsBase.sol";

/// Public wrapper exposing the internal deploy-base helpers so a `Test` can drive
/// them without inheriting `Script` (avoids the Test/Script diamond). Inherits both
/// families; constants + the `ShrincsVerifier` struct come along.
contract DeployHarness is DeployWotsBase, DeployShrincsBase {
    function wotsLib(Deployer d, uint256 pk) public returns (address) {
        return _deployWotsPlusLib(d, pk);
    }

    function factory(Deployer d, uint256 pk, address owner, uint256 maxFee) public returns (address) {
        return _deployFactory(d, pk, owner, maxFee);
    }

    function shrincsImpl(Deployer d, uint256 pk, address f) public returns (address) {
        return _deployShrincsImplAndVet(d, pk, f);
    }

    function shrincsPaymaster(Deployer d, uint256 pk, address owner, bytes32 commitment, uint32 hashSuite, uint32 maxSig)
        public
        returns (address)
    {
        return _deployShrincsPaymaster(
            d, pk, ShrincsVerifier({paymasterOwner: owner, commitment: commitment, hashSuite: hashSuite, maxSignatures: maxSig})
        );
    }

    function wotsImpl(Deployer d, uint256 pk, address f) public returns (address) {
        return _deployWotsImplAndVet(d, pk, f);
    }

    function quipPaymaster(Deployer d, uint256 pk, address owner) public returns (address) {
        return _deployQuipPaymaster(d, pk, owner);
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
    bytes32 internal constant FACTORY_PROXY_SALT = keccak256("QUIP:QuipFactory:Proxy:V2");
    bytes32 internal constant WOTS_IMPL_SALT = keccak256("QUIP:WOTSPlusImplementation:V1.1");
    bytes32 internal constant QUIP_PAYMASTER_PROXY_SALT = keccak256("QUIP:QuipPaymaster:Proxy:V1.1");
    // Impl salts bind the verifier scheme tag (PROFILE_TAG = the profile-name
    // hash), spelled out literally here per the independent-copy rule above.
    bytes32 internal constant SHRINCS_WALLET_SALT =
        keccak256(abi.encodePacked("QUIP:ShrincsWallet:V1.1:", keccak256("shrincs-256s-keccak")));
    bytes32 internal constant SHRINCS_PAYMASTER_PROXY_SALT = keccak256("QUIP:ShrincsPaymaster:Proxy:V1.1");

    address internal owner;
    Deployer internal deployer;
    DeployHarness internal h;

    function setUp() public {
        owner = vm.addr(PK);
        vm.deal(owner, 100 ether);
        deployer = new Deployer();
        h = new DeployHarness();
        // Real-chain precondition mirrored locally: the deploy base's
        // `_requireExists` gate expects the canonical hashsigs-solidity CREATE3
        // deploys (sibling + SHRINCS verifier) to already exist.
        vm.etch(0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A, address(new SHRINCS256sKeccak()).code);
        vm.etch(0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A, address(new SPHINCSPlusC256sKeccak()).code);
    }

    function _predict(bytes32 salt) internal view returns (address) {
        return CREATE3.predictDeterministicAddress(salt, address(deployer));
    }

    /// DeployAll's ordering: shared infra, Shrincs (vetted first), WOTS+ (vetted
    /// last). Asserts every contract lands at its predicted CREATE3 address, both
    /// impls vet, and WOTS+ is `latest`.
    function test_deployAll_predictedAddresses_bothVetted_wotsLatest() public {
        address lib = h.wotsLib(deployer, PK);
        address fAddr = h.factory(deployer, PK, owner, MAX_FEE);
        address sImpl = h.shrincsImpl(deployer, PK, fAddr);
        address sPm = h.shrincsPaymaster(
            deployer, PK, owner, VERIFIER_COMMITMENT, HashSuite.HASH_SUITE_ID, VERIFIER_MAX_SIGS
        );
        address wImpl = h.wotsImpl(deployer, PK, fAddr);
        address qPm = h.quipPaymaster(deployer, PK, owner);

        // Deterministic CREATE3 addresses (relative to this local Deployer).
        assertEq(lib, _predict(WOTSPLUS_SALT), "WOTSPlus addr");
        assertEq(fAddr, _predict(FACTORY_PROXY_SALT), "QuipFactory proxy addr");
        assertEq(sImpl, _predict(SHRINCS_WALLET_SALT), "ShrincsWallet addr");
        assertEq(sPm, _predict(SHRINCS_PAYMASTER_PROXY_SALT), "ShrincsPaymaster proxy addr");
        assertEq(wImpl, _predict(WOTS_IMPL_SALT), "WOTSPlusImplementation addr");
        assertEq(qPm, _predict(QUIP_PAYMASTER_PROXY_SALT), "QuipPaymaster proxy addr");

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
        h.wotsLib(deployer, PK);
        address fAddr = h.factory(deployer, PK, owner, MAX_FEE);
        h.wotsImpl(deployer, PK, fAddr); // WOTS+ vetted first -> latest
        address sImpl = h.shrincsImpl(deployer, PK, fAddr); // Shrincs vetted last -> latest
        assertEq(IVettingFactory(fAddr).latestWalletImpl(), sImpl, "shrincs latest after standalone");
    }

    /// Re-running every step is a no-op (skip-if-deployed / skip-if-vetted), never
    /// reverting `AlreadyVetted` or a CREATE3 collision.
    function test_idempotent_reRunIsNoOp() public {
        h.wotsLib(deployer, PK);
        address fAddr = h.factory(deployer, PK, owner, MAX_FEE);
        address sImpl1 = h.shrincsImpl(deployer, PK, fAddr);
        address wImpl1 = h.wotsImpl(deployer, PK, fAddr);

        // Second pass — identical addresses, no revert.
        h.wotsLib(deployer, PK);
        address fAddr2 = h.factory(deployer, PK, owner, MAX_FEE);
        address sImpl2 = h.shrincsImpl(deployer, PK, fAddr);
        address wImpl2 = h.wotsImpl(deployer, PK, fAddr);

        assertEq(fAddr, fAddr2, "factory stable");
        assertEq(sImpl1, sImpl2, "shrincs impl stable");
        assertEq(wImpl1, wImpl2, "wots impl stable");
    }
}
