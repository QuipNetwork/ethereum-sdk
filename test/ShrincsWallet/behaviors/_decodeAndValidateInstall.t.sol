// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_decodeAndValidateInstall` payload decoder: field
///      round-trip, the suite agreement checks, and the main-only signing-budget guard. Bundle
///      validation/recording is `_safeInstallKeyBundle`'s job and is tested there.
contract ShrincsWallet__decodeAndValidateInstall is ShrincsWalletTest {
    function test_decodeAndValidateInstall_decodesFields() public view {
        (
            bytes32 declaredCommitment,
            uint32 maxSignatures,
            SHRINCS.PublicKey memory mainKey,
            SHRINCS.PublicKey memory erc1271Key
        ) = wallet.exposed_decodeAndValidateInstall(_validInitPayload());

        assertEq(declaredCommitment, mainCommitment, "declared commitment");
        assertEq(maxSignatures, MAX_SIG, "maxSignatures from the main stateful key");
        assertEq(mainKey.statefulPublicKey, mainPk.statefulPublicKey, "main bundle round-trips");
        assertEq(erc1271Key.statefulPublicKey, erc1271Pk.statefulPublicKey, "erc1271 bundle round-trips");
        assertEq(erc1271Key.pkSeed, erc1271Pk.pkSeed, "erc1271 stateless seed round-trips");
    }

    function test_decodeAndValidateInstall_revertsWhen_unsupportedHashSuite() public {
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(mainPk.pkSeed), _mainPk(),
            SHRINCS.HASH_SUITE_UNSUPPORTED, erc1271Pk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.exposed_decodeAndValidateInstall(payload);
    }

    function test_decodeAndValidateInstall_revertsWhen_unsupportedErc1271HashSuite() public {
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(mainPk.pkSeed), _mainPk(),
            HashSuite.HASH_SUITE_ID, erc1271Pk, SHRINCS.HASH_SUITE_UNSUPPORTED
        );
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.exposed_decodeAndValidateInstall(payload);
    }

    function test_decodeAndValidateInstall_revertsWhen_zeroMaxSignatures() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        bytes memory spk = pk.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0;
        pk.statefulPublicKey = spk;
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(pk.pkSeed), pk,
            HashSuite.HASH_SUITE_ID, erc1271Pk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.exposed_decodeAndValidateInstall(payload);
    }

    function test_decodeAndValidateInstall_revertsWhen_malformedStatefulKeyLength() public {
        SHRINCS.PublicKey memory pk = _mainPk();
        pk.statefulPublicKey = hex"00112233"; // undecodable 68-byte encoding
        bytes memory payload = _buildInitPayload(
            mainCommitment, _toBytes32(pk.pkSeed), pk,
            HashSuite.HASH_SUITE_ID, erc1271Pk, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.exposed_decodeAndValidateInstall(payload);
    }
}
