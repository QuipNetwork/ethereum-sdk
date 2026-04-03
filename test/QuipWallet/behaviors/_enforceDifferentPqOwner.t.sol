// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet__enforceDifferentPqOwner is QuipWalletTest {
    QuipWalletHarness public harnessProxy;
    WOTSPlus.WinternitzAddress public hPubkey;

    function setUp() public override {
        super.setUp();
        // Vet harness as an implementation so we can deploy a proxy backed by it
        QuipWalletHarness harnessImpl = new QuipWalletHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-diff");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);
        hPubkey = pub;

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            keccak256("h-diff-vault"), payable(ALICE), payload
        );
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function test_exposed_enforceDifferentPqOwner_acceptsDifferentKey() public view {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xaa)),
            publicKeyHash: bytes32(uint256(0xbb))
        });
        harnessProxy.exposed_enforceDifferentPqOwner(key);
    }

    function test_exposed_enforceDifferentPqOwner_acceptsDifferentSeedSameHash() public view {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xaa)),
            publicKeyHash: hPubkey.publicKeyHash
        });
        harnessProxy.exposed_enforceDifferentPqOwner(key);
    }

    function test_exposed_enforceDifferentPqOwner_acceptsSameSeedDifferentHash() public view {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: hPubkey.publicSeed,
            publicKeyHash: bytes32(uint256(0xbb))
        });
        harnessProxy.exposed_enforceDifferentPqOwner(key);
    }

    function test_exposed_enforceDifferentPqOwner_revertsWhen_sameKey() public {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: hPubkey.publicSeed,
            publicKeyHash: hPubkey.publicKeyHash
        });
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        harnessProxy.exposed_enforceDifferentPqOwner(key);
    }
}
