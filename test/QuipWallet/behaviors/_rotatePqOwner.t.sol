// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet__rotatePqOwner is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-rotate");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            keccak256("h-rotate-vault"), payable(ALICE), payload
        );
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function test_exposed_rotatePqOwner_updatesPqOwner() public {
        WOTSPlus.WinternitzAddress memory newKey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xaa)),
            publicKeyHash: bytes32(uint256(0xbb))
        });

        harnessProxy.exposed_rotatePqOwner(newKey);

        (bytes32 seed, bytes32 hash) = harnessProxy.pqOwner();
        assertEq(seed, newKey.publicSeed);
        assertEq(hash, newKey.publicKeyHash);
    }

    function test_exposed_rotatePqOwner_emitsPqOwnerRotated() public {
        (bytes32 oldSeed, bytes32 oldHash) = harnessProxy.pqOwner();
        WOTSPlus.WinternitzAddress memory oldKey = WOTSPlus.WinternitzAddress({
            publicSeed: oldSeed,
            publicKeyHash: oldHash
        });

        WOTSPlus.WinternitzAddress memory newKey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(0xcc)),
            publicKeyHash: bytes32(uint256(0xdd))
        });

        vm.recordLogs();
        harnessProxy.exposed_rotatePqOwner(newKey);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs[0].topics[0], IQuipWallet.PqOwnerRotated.selector);

        (
            WOTSPlus.WinternitzAddress memory emittedOld,
            WOTSPlus.WinternitzAddress memory emittedNew
        ) = abi.decode(logs[0].data, (WOTSPlus.WinternitzAddress, WOTSPlus.WinternitzAddress));

        assertEq(emittedOld.publicSeed, oldKey.publicSeed);
        assertEq(emittedOld.publicKeyHash, oldKey.publicKeyHash);
        assertEq(emittedNew.publicSeed, newKey.publicSeed);
        assertEq(emittedNew.publicKeyHash, newKey.publicKeyHash);
    }
}
