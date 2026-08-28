// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness, HarnessKeyset} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlusCodec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusStorage as Storage} from "../../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

contract WOTSPlusImplementation__verifyInitialState is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    /// @dev ERC-7201 base slot for WOTSPlusStorage.Layout. Imported so any
    ///      drift between this test and the storage library shows up here.
    bytes32 constant STORAGE_BASE = Storage._WOTSPLUS_STORAGE_SLOT;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-verify");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-verify-vault"), payable(ALICE), payload
        );
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    /// @dev Uninitialized harness with factory + disaster key populated so later
    ///      gates (ownership, txn count) can fire independently.
    function _bareWithFactoryAndDisaster() internal returns (WOTSPlusImplementationHarness bare) {
        bare = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.store(address(bare), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 1), bytes32(uint256(1)));
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 2), bytes32(uint256(2)));
    }

    function _expectVerifyInitialStateRevert(WOTSPlusImplementationHarness bare, bytes4 selector) internal {
        vm.expectRevert(selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_passesWhenValid() public view {
        harnessProxy.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_zeroFactory() public {
        WOTSPlusImplementationHarness bare = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.expectRevert(IWOTSPlusImplementation.ZeroAddressFactory.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_wrongTransactionKeyCount() public {
        WOTSPlusImplementationHarness bare = _bareWithFactoryAndDisaster();
        // Set ownershipKey (slots 3 + 4) to non-zero — txn keyset remains empty,
        // so the count check should fire.
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 3), bytes32(uint256(3)));
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 4), bytes32(uint256(4)));
        _expectVerifyInitialStateRevert(bare, IWOTSPlusImplementation.IncorrectTransactionKeyAmount.selector);
    }

    function test_exposed_verifyInitialState_revertsWhen_disasterKeyZero() public {
        WOTSPlusImplementationHarness bare = new WOTSPlusImplementationHarness(payable(address(factory)));
        // Set quipFactory only; disaster key and keysets remain zero.
        vm.store(address(bare), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_ownershipKeyZero() public {
        WOTSPlusImplementationHarness bare = _bareWithFactoryAndDisaster();
        // Leave ownershipKey (slots 3 + 4) zero; the ownership-key check should fire.
        _expectVerifyInitialStateRevert(bare, IWOTSPlusImplementation.UnknownOwnershipKey.selector);
    }

    function test_exposed_verifyInitialState_revertsWhen_disasterKeySeedZero() public {
        WOTSPlusImplementationHarness bare = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.store(address(bare), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        // disaster.seed stays zero; disaster.hash set non-zero so we exercise the
        // "seed-only zero" branch of the guard.
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 2), bytes32(uint256(0x11)));
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_disasterKeyHashZero() public {
        WOTSPlusImplementationHarness bare = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.store(address(bare), STORAGE_BASE, bytes32(uint256(uint160(address(factory)))));
        // disaster.seed non-zero, disaster.hash stays zero.
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 1), bytes32(uint256(0x22)));
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_ownershipKeySeedZero() public {
        WOTSPlusImplementationHarness bare = _bareWithFactoryAndDisaster();
        // ownership.seed stays zero; ownership.hash non-zero.
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 4), bytes32(uint256(0x33)));
        _expectVerifyInitialStateRevert(bare, IWOTSPlusImplementation.UnknownOwnershipKey.selector);
    }

    function test_exposed_verifyInitialState_revertsWhen_ownershipKeyHashZero() public {
        WOTSPlusImplementationHarness bare = _bareWithFactoryAndDisaster();
        // ownership.seed non-zero, ownership.hash stays zero.
        vm.store(address(bare), bytes32(uint256(STORAGE_BASE) + 3), bytes32(uint256(0x44)));
        _expectVerifyInitialStateRevert(bare, IWOTSPlusImplementation.UnknownOwnershipKey.selector);
    }

    // Transaction keyset correctly sized but recovery count wrong — the recovery
    // length check is the last gate `_verifyInitialState` performs.
    function test_exposed_verifyInitialState_revertsWhen_wrongRecoveryKeyCount() public {
        // Use the already-initialised `harnessProxy` (5 txn keys, 10 rec keys) and
        // clear the recovery keyset after init so the recovery-count gate fires.
        harnessProxy.exposed_clearKeys(HarnessKeyset.Recovery);
        assertEq(harnessProxy.keyCount(WOTSPlusCodec.KeyType.Recovery), 0);
        vm.expectRevert(IWOTSPlusImplementation.IncorrectRecoveryKeyAmount.selector);
        harnessProxy.exposed_verifyInitialState();
    }
}
