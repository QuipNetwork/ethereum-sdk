// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

/// @dev Tests for dynamic _addRecoveryKeys(WinternitzAddress[] calldata)
contract QuipWallet___addRecoveryKeys is QuipWalletTest {
    QuipWalletHarness public harnessProxy;
    QuipWalletHarness public bare;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        // Proxy with 10 recovery keys from init
        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-addkeys");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            keccak256("h-addkeys-vault"), payable(ALICE), payload
        );
        harnessProxy = QuipWalletHarness(payable(proxyAddr));

        // Bare harness with empty storage
        bare = new QuipWalletHarness(payable(address(factory)));
    }

    function _makeKey(uint256 seed) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(seed),
            publicKeyHash: bytes32(seed + 1000)
        });
    }

    function _makeKeys(uint256 startSeed, uint256 count)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[] memory keys)
    {
        keys = new WOTSPlus.WinternitzAddress[](count);
        for (uint256 i = 0; i < count; i++) {
            keys[i] = _makeKey(startSeed + i * 2);
        }
    }

    function test_exposed_addRecoveryKeys_addsSingleKey() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xa000, 1);
        bare.exposed_addRecoveryKeys(keys);
        assertEq(bare.getRecoveryKeyCount(), 1);
        bytes32 expectedHash = EfficientHashLib.hash(keys[0].publicSeed, keys[0].publicKeyHash);
        assertTrue(bare.isRecoveryKey(expectedHash));
    }

    function test_exposed_addRecoveryKeys_addsMultipleKeys() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xb000, 3);
        bare.exposed_addRecoveryKeys(keys);
        assertEq(bare.getRecoveryKeyCount(), 3);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 expectedHash = EfficientHashLib.hash(keys[i].publicSeed, keys[i].publicKeyHash);
            assertTrue(bare.isRecoveryKey(expectedHash));
        }
    }

    function test_exposed_addRecoveryKeys_addsUpToMax() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xc000, 10);
        bare.exposed_addRecoveryKeys(keys);
        assertEq(bare.getRecoveryKeyCount(), 10);
    }

    function test_exposed_addRecoveryKeys_revertsWhen_emptyArray() public {
        WOTSPlus.WinternitzAddress[] memory empty = new WOTSPlus.WinternitzAddress[](0);
        vm.expectRevert(IQuipWallet.EmptyRecoveryKeys.selector);
        harnessProxy.exposed_addRecoveryKeys(empty);
    }

    function test_exposed_addRecoveryKeys_revertsWhen_zeroSeedInKey() public {
        WOTSPlus.WinternitzAddress[] memory keys = new WOTSPlus.WinternitzAddress[](1);
        keys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        harnessProxy.exposed_addRecoveryKeys(keys);
    }

    function test_exposed_addRecoveryKeys_revertsWhen_zeroHashInKey() public {
        WOTSPlus.WinternitzAddress[] memory keys = new WOTSPlus.WinternitzAddress[](1);
        keys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        harnessProxy.exposed_addRecoveryKeys(keys);
    }

    function test_exposed_addRecoveryKeys_revertsWhen_duplicateKey() public {
        WOTSPlus.WinternitzAddress[] memory keys = new WOTSPlus.WinternitzAddress[](2);
        keys[0] = _makeKey(0xdead);
        keys[1] = _makeKey(0xdead);
        vm.expectRevert(IQuipWallet.DuplicateRecoveryKey.selector);
        bare.exposed_addRecoveryKeys(keys);
    }

    // Note: proxy already has 10 keys from init, so adding more exceeds MAX
    function test_exposed_addRecoveryKeys_revertsWhen_exceedsMax() public {
        WOTSPlus.WinternitzAddress[] memory keys = _makeKeys(0xff00, 1);
        vm.expectRevert(); // Solady EnumerableSetLib overflow
        harnessProxy.exposed_addRecoveryKeys(keys);
    }
}

/// @dev Tests for fixed-size _addRecoveryKeys(WinternitzAddress[10] calldata)
contract QuipWallet___addRecoveryKeysFixed is QuipWalletTest {
    QuipWalletHarness public harness;

    function setUp() public override {
        super.setUp();
        harness = new QuipWalletHarness(payable(address(factory)));
    }

    function _makeFixedKeys(uint256 startSeed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[10] memory keys)
    {
        for (uint256 i = 0; i < 10; i++) {
            keys[i] = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(startSeed + i * 2),
                publicKeyHash: bytes32(startSeed + i * 2 + 1000)
            });
        }
    }

    function test_exposed_addRecoveryKeysFixed_addsAllTenKeys() public {
        WOTSPlus.WinternitzAddress[10] memory keys = _makeFixedKeys(0x100);
        harness.exposed_addRecoveryKeysFixed(keys);
        assertEq(harness.getRecoveryKeyCount(), 10);
    }

    function test_exposed_addRecoveryKeysFixed_revertsWhen_zeroFieldInAnyKey() public {
        WOTSPlus.WinternitzAddress[10] memory keys = _makeFixedKeys(0x100);
        keys[5].publicSeed = bytes32(0);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        harness.exposed_addRecoveryKeysFixed(keys);
    }

    function test_exposed_addRecoveryKeysFixed_revertsWhen_duplicateInArray() public {
        WOTSPlus.WinternitzAddress[10] memory keys = _makeFixedKeys(0x200);
        keys[7] = keys[3];
        vm.expectRevert(IQuipWallet.DuplicateRecoveryKey.selector);
        harness.exposed_addRecoveryKeysFixed(keys);
    }
}
