// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
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
}
