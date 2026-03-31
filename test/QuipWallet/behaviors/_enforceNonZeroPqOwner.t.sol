// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet___enforceNonZeroPqOwner is QuipWalletTest {
    QuipWalletHarness public harness;

    function setUp() public override {
        super.setUp();
        harness = new QuipWalletHarness(payable(address(factory)));
    }

    function test_exposed_enforceNonZeroPqOwner_acceptsValidKey() public view {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(uint256(2))
        });
        harness.exposed_enforceNonZeroPqOwner(key);
    }

    function test_exposed_enforceNonZeroPqOwner_revertsWhen_zeroSeed() public {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(2))
        });
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        harness.exposed_enforceNonZeroPqOwner(key);
    }

    function test_exposed_enforceNonZeroPqOwner_revertsWhen_zeroHash() public {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        harness.exposed_enforceNonZeroPqOwner(key);
    }

    function test_exposed_enforceNonZeroPqOwner_revertsWhen_bothZero() public {
        WOTSPlus.WinternitzAddress memory key = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        harness.exposed_enforceNonZeroPqOwner(key);
    }
}
