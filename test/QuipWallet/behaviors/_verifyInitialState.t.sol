// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet__verifyInitialState is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    /// @dev ERC-7201 base slot for WOTSPlusStorage.Layout
    bytes32 constant STORAGE_BASE = 0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-verify");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            keccak256("h-verify-vault"), payable(ALICE), payload
        );
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function test_exposed_verifyInitialState_passesWhenValid() public view {
        harnessProxy.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_zeroFactory() public {
        QuipWalletHarness bare = new QuipWalletHarness(payable(address(factory)));
        vm.expectRevert(IQuipWallet.ZeroAddressFactory.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_zeroPqOwner() public {
        QuipWalletHarness bare = new QuipWalletHarness(payable(address(factory)));
        // Set quipFactory (slot 0) to non-zero, pqOwner remains zero
        vm.store(address(bare), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_wrongRecoveryKeyCount() public {
        QuipWalletHarness bare = new QuipWalletHarness(payable(address(factory)));
        // Set quipFactory (slot 0)
        vm.store(address(bare), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        // Set pqOwner.publicSeed (slot 1) and pqOwner.publicKeyHash (slot 2)
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 1), bytes32(uint256(1)));
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 2), bytes32(uint256(2)));
        // Recovery key count is 0 != MAX_KEYS (10)
        vm.expectRevert(IQuipWallet.IncorrectRecoveryKeyAmount.selector);
        bare.exposed_verifyInitialState();
    }
}
