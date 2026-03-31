// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet___upgradeGuard is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-guard");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            keccak256("h-guard-vault"), payable(ALICE), payload
        );
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function test_exposed_upgradeGuard_returnsZeroByDefault() public view {
        assertEq(harnessProxy.exposed_upgradeGuard(), 0);
    }

    function test_exposed_upgradeGuard_returnsNonZeroDuringUpgrade() public {
        assertEq(harnessProxy.exposed_upgradeGuardInContext(), 1);
    }
}
