// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_setPqVerifier is QuipPaymasterTest {
    function test_setPqVerifier_setsVerifierKey() public {
        address wallet2 = makeAddr("wallet2");
        (WOTSPlus.WinternitzAddress memory key, ) = _generateKeyPair(
            "wallet2-verifier"
        );

        vm.prank(ADMIN);
        paymaster.setPqVerifier(wallet2, key);

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(wallet2);
        assertEq(v.publicSeed, key.publicSeed);
        assertEq(v.publicKeyHash, key.publicKeyHash);
    }

    function test_setPqVerifier_overwritesExistingKey() public {
        // WALLET already has a verifier from setUp — overwrite it
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "overwrite-key"
        );

        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET, newKey);

        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, newKey.publicSeed);
        assertEq(v.publicKeyHash, newKey.publicKeyHash);
    }

    function test_setPqVerifier_emitsPqVerifierSet() public {
        address wallet2 = makeAddr("wallet2");
        (WOTSPlus.WinternitzAddress memory key, ) = _generateKeyPair(
            "wallet2-verifier"
        );

        vm.prank(ADMIN);
        vm.expectEmit(true, false, false, true);
        emit IQuipPaymaster.PqVerifierSet(wallet2, key);
        paymaster.setPqVerifier(wallet2, key);
    }

    function test_setPqVerifier_revertsWhen_notOwner() public {
        address wallet2 = makeAddr("wallet2");
        (WOTSPlus.WinternitzAddress memory key, ) = _generateKeyPair(
            "wallet2-verifier"
        );

        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.setPqVerifier(wallet2, key);
    }

    function test_setPqVerifier_revertsWhen_zeroPublicSeed() public {
        address wallet2 = makeAddr("wallet2");
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.ZeroValuePqVerifierKey.selector);
        paymaster.setPqVerifier(wallet2, key);
    }

    function test_setPqVerifier_revertsWhen_zeroPublicKeyHash() public {
        address wallet2 = makeAddr("wallet2");
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });

        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.ZeroValuePqVerifierKey.selector);
        paymaster.setPqVerifier(wallet2, key);
    }
}
