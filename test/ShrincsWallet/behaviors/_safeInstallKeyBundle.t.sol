// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_safeInstallKeyBundle` whole-bundle install: shape
///      validation, on-chain commitment derivation, and the registry recording of BOTH halves.
contract ShrincsWallet__safeInstallKeyBundle is ShrincsWalletTest {
    function _freshBundle(bytes memory seed) internal view returns (SHRINCS.PublicKey memory pk) {
        bool ok;
        (, pk, ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "keygen");
    }

    function test_safeInstallKeyBundle_returnsDerivedCommitment() public {
        SHRINCS.PublicKey memory pk = _freshBundle("bundle-derives");
        assertEq(wallet.exposed_safeInstallKeyBundle(pk), _commitment32(pk), "commitment derived on-chain");
    }

    function test_safeInstallKeyBundle_installsBothHalves() public {
        SHRINCS.PublicKey memory pk = _freshBundle("bundle-installs");
        _assertTreesUnspent(pk);
        wallet.exposed_safeInstallKeyBundle(pk);
        _assertTreesSpent(pk);
    }

    function test_safeInstallKeyBundle_revertsWhen_invalidBundle() public {
        SHRINCS.PublicKey memory pk = _freshBundle("bundle-invalid");
        pk.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-embedded-commitment"));
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.exposed_safeInstallKeyBundle(pk);
    }

    function test_safeInstallKeyBundle_revertsWhen_repeatInstall() public {
        SHRINCS.PublicKey memory pk = _freshBundle("bundle-repeat");
        wallet.exposed_safeInstallKeyBundle(pk);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(pk.statefulPublicKey))
        );
        wallet.exposed_safeInstallKeyBundle(pk);
    }

    function test_safeInstallKeyBundle_revertsWhen_statefulHalfHeld() public {
        // Fresh stateless root under the wallet's installed STATEFUL subkey.
        SHRINCS.PublicKey memory pk = _freshBundle("bundle-stateful-held");
        pk.statefulPublicKey = mainPk.statefulPublicKey;
        pk.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, pk.pkSeed, pk.hypertreeRoot)
        );
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.exposed_safeInstallKeyBundle(pk);
    }

    function test_safeInstallKeyBundle_revertsWhen_statelessHalfHeld() public {
        // Fresh stateful subkey over the wallet's installed recovery root.
        SHRINCS.PublicKey memory pk = _bundleSharingStatelessRoot("bundle-stateless-held", mainPk);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.exposed_safeInstallKeyBundle(pk);
    }
}
