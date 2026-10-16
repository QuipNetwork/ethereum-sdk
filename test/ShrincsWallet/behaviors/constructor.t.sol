// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev A verifier whose PROFILE_TAG does not match the profile this wallet build was
///      compiled under — must be rejected by the constructor's profile drift guard.
contract WrongProfileVerifier {
    bytes32 public constant PROFILE_TAG = keccak256("shrincs-wrong-profile");
}

/// @dev Behavior tests for the ShrincsWallet constructor — the explicit revert branches
///      (zero factory, zero verifier, wrong-profile verifier) and the happy-path immutable
///      assignments, plus the EIP-712 domain name's binding to the verifier profile.
contract ShrincsWallet_constructor is ShrincsWalletTest {
    function test_constructor_setsImmutables() public {
        ShrincsWalletHarness fresh =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        assertEq(fresh.FACTORY(), address(factory), "factory immutable");
        assertEq(fresh.SHRINCS_VERIFIER(), address(shrincsVerifier), "verifier immutable");
        assertEq(fresh.getShrincsVerifier(), address(shrincsVerifier), "verifier view getter");
    }

    function test_constructor_revertsWhen_factoryZero() public {
        vm.expectRevert(IShrincsWallet.ZeroAddressFactory.selector);
        new ShrincsWalletHarness(payable(address(0)), address(shrincsVerifier));
    }

    function test_constructor_revertsWhen_verifierZero() public {
        vm.expectRevert(IShrincsWallet.ZeroAddressVerifier.selector);
        new ShrincsWalletHarness(payable(address(factory)), address(0));
    }

    function test_constructor_revertsWhen_verifierProfileMismatch() public {
        WrongProfileVerifier wrong = new WrongProfileVerifier();
        vm.expectRevert(IShrincsWallet.VerifierProfileMismatch.selector);
        new ShrincsWalletHarness(payable(address(factory)), address(wrong));
    }

    /// @dev The EIP-712 domain name embeds the verifier's profile identity: PROFILE_NAME's
    ///      keccak IS the pinned verifier's PROFILE_TAG (the constructor guard enforces the
    ///      pairing), so an ECDSA owner signature cannot cross SHRINCS profiles.
    function test_domainName_embedsVerifierProfile() public {
        ShrincsWalletHarness fresh =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        (, string memory name, string memory version,,,,) = fresh.eip712Domain();
        assertEq(
            name,
            string.concat("QuipShrincsWallet/", SHRINCSParams.PROFILE_NAME, "/v1"),
            "domain name"
        );
        assertEq(version, "1", "domain version");
        assertEq(
            keccak256(bytes(SHRINCSParams.PROFILE_NAME)),
            shrincsVerifier.PROFILE_TAG(),
            "PROFILE_NAME keccak must equal the pinned verifier's PROFILE_TAG"
        );
    }

    /// @dev Address-bound runtime code: `address(this)` lives in immutables (Solady EIP712's
    ///      cached domain fields and the wallet's `_SELF`), so two deployments of the same source
    ///      with identical constructor args have DIFFERENT codehashes. Consequences for the
    ///      factory's codehash-keyed registry: a redeploy is unvetted, so
    ///      `undeprecateImplementation`'s same-codehash re-bind can never move the pointer off
    ///      the original address for this family, and replacing an implementation with a redeploy
    ///      is the two-call vet-new / deprecate-old flow.
    function test_constructor_redeployHasDistinctCodehash_undeprecateCannotRebind() public {
        ShrincsWalletHarness redeploy =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        assertTrue(address(redeploy) != address(walletImplementation));
        assertEq(redeploy.FACTORY(), walletImplementation.FACTORY(), "same constructor args");
        assertEq(redeploy.SHRINCS_VERIFIER(), walletImplementation.SHRINCS_VERIFIER(), "same constructor args");
        assertTrue(
            address(redeploy).codehash != address(walletImplementation).codehash,
            "address(this) immutables make every deployment a distinct codehash"
        );

        // The redeploy cannot ride the original's vetting.
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.ImplementationNotVetted.selector);
        factory.undeprecateImplementation(address(redeploy));

        // Only the original address can be reactivated — the re-bind is a self-assign.
        vm.prank(ADMIN);
        factory.undeprecateImplementation(address(walletImplementation));
        assertEq(factory.vettedWalletImpls(address(walletImplementation).codehash), address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(walletImplementation));

        // The documented replacement path: vet the redeploy as a NEW entry, deprecate the old.
        vm.prank(ADMIN);
        factory.vetImplementation(address(redeploy));
        assertEq(factory.latestWalletImpl(), address(redeploy), "redeploy vets as a new entry and becomes latest");
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));
        assertEq(factory.latestWalletImpl(), address(redeploy));
        assertEq(factory.getVettedCodeCount(), 2, "two distinct codehashes for one source");
    }

    function test_constructor_revertsWhen_implementationInitialized() public {
        ShrincsWalletHarness fresh =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        fresh.initialize(payable(OWNER), _validInitPayload());
    }
}
