// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness, HarnessKeyset} from "../../harness/QuipWalletHarness.sol";
import {WOTSPlusCodec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
contract QuipWallet__verifyInitialState is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    /// @dev ERC-7201 base slot for WOTSPlusStorage.Layout
    bytes32 constant STORAGE_BASE =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (
            WOTSPlus.WinternitzAddress memory pub,
            bytes32 priv
        ) = _generateKeyPair("h-verify");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            priv,
            10
        );
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("h-verify-vault"), payable(ALICE), payload);
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function test_exposed_verifyInitialState_passesWhenValid() public view {
        harnessProxy.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_zeroFactory() public {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.expectRevert(IQuipWallet.ZeroAddressFactory.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_wrongTransactionKeyCount()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        // Set quipFactory (slot 0), disasterRecoveryKey (slots 1 + 2), ownershipKey
        // (slots 3 + 4) to non-zero — txn keyset remains empty, so the count check
        // should fire.
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 1),
            bytes32(uint256(1))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 2),
            bytes32(uint256(2))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 3),
            bytes32(uint256(3))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 4),
            bytes32(uint256(4))
        );
        vm.expectRevert(IQuipWallet.IncorrectTransactionKeyAmount.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_disasterKeyZero()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        // Set quipFactory only; disaster key and keysets remain zero.
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_ownershipKeyZero()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        // Set quipFactory (slot 0) and disasterRecoveryKey (slots 1 + 2). Leave
        // ownershipKey (slots 3 + 4) zero; the ownership-key check should fire.
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 1),
            bytes32(uint256(1))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 2),
            bytes32(uint256(2))
        );
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_disasterKeySeedZero()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        // disaster.seed stays zero; disaster.hash set non-zero so we exercise the
        // "seed-only zero" branch of the guard.
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 2),
            bytes32(uint256(0x11))
        );
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_disasterKeyHashZero()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        // disaster.seed non-zero, disaster.hash stays zero.
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 1),
            bytes32(uint256(0x22))
        );
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_ownershipKeySeedZero()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        // Valid disaster key (both fields non-zero).
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 1),
            bytes32(uint256(1))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 2),
            bytes32(uint256(2))
        );
        // ownership.seed stays zero; ownership.hash non-zero.
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 4),
            bytes32(uint256(0x33))
        );
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        bare.exposed_verifyInitialState();
    }

    function test_exposed_verifyInitialState_revertsWhen_ownershipKeyHashZero()
        public
    {
        QuipWalletHarness bare = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.store(
            address(bare),
            STORAGE_BASE,
            bytes32(uint256(uint160(address(factory))))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 1),
            bytes32(uint256(1))
        );
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 2),
            bytes32(uint256(2))
        );
        // ownership.seed non-zero, ownership.hash stays zero.
        vm.store(
            address(bare),
            bytes32(uint256(STORAGE_BASE) + 3),
            bytes32(uint256(0x44))
        );
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        bare.exposed_verifyInitialState();
    }

    // Transaction keyset correctly sized but recovery count wrong — the recovery
    // length check is the last gate `_verifyInitialState` performs.
    function test_exposed_verifyInitialState_revertsWhen_wrongRecoveryKeyCount()
        public
    {
        // Use the already-initialised `harnessProxy` (5 txn keys, 10 rec keys) and
        // clear the recovery keyset after init so the recovery-count gate fires.
        harnessProxy.exposed_clearKeys(HarnessKeyset.Recovery);
        assertEq(harnessProxy.keyCount(WOTSPlusCodec.KeyType.Recovery), 0);
        vm.expectRevert(IQuipWallet.IncorrectRecoveryKeyAmount.selector);
        harnessProxy.exposed_verifyInitialState();
    }
}
