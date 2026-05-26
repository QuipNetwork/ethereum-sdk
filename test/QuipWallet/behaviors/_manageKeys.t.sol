// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

/// @dev Behaviour tests for `_manageKeys(payload, replace)`. Shared worker for
///      `addKeys` (replace=false) and `refreshKeys` (replace=true). Decodes a
///      keyManagement payload, rotates the tx auth key, then either appends
///      (`addKeys`) or clears+repopulates (`refreshKeys`) the target keyset.
contract QuipWallet__manageKeys is QuipWalletTest {
    QuipWalletHarness public harnessProxy;

    WOTSPlus.WinternitzAddress internal currentKey;
    bytes32 internal currentPriv;

    function setUp() public override {
        super.setUp();
        QuipWalletHarness harnessImpl = new QuipWalletHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (currentKey, currentPriv) = _generateKeyPair("h-mk-current");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            currentPriv,
            10
        );
        bytes memory payload = _encodeInitPayload(currentKey, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("h-mk-vault"), payable(ALICE), payload);
        harnessProxy = QuipWalletHarness(payable(proxyAddr));
    }

    function _mkKey(
        uint256 seed
    ) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return
            WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(seed),
                publicKeyHash: bytes32(seed + 1000)
            });
    }

    function _mkKeys(
        uint256 startSeed,
        uint256 n
    ) internal pure returns (WOTSPlus.WinternitzAddress[] memory arr) {
        arr = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) arr[i] = _mkKey(startSeed + i * 2);
    }

    function _encodePayload(
        Codec.KeyType kind,
        bool replace,
        WOTSPlus.WinternitzAddress memory cur,
        bytes32 curPriv,
        WOTSPlus.WinternitzAddress memory next,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes memory) {
        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newKeys));
        bytes32 digest = Codec.keysetDigest(
            kind,
            replace,
            address(harnessProxy),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            next.publicSeed,
            next.publicKeyHash,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(curPriv, digest);
        return Codec.encodeKeyManagement(kind, cur, next, sig, newKeys);
    }

    /*────────────────────────── add (replace=false) ──────────────────────────*/

    function test_exposed_manageKeys_add_verification_appends() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-v-next");
        WOTSPlus.WinternitzAddress[] memory keys = _mkKeys(0x1000, 2);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            false,
            currentKey,
            currentPriv,
            next,
            keys
        );

        harnessProxy.exposed_manageKeys(payload, false);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 2);
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, keys[0]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, keys[1]));
        // Auth rotation committed on the transaction keyset.
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, currentKey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, next));
    }

    function test_exposed_manageKeys_add_transaction_appends() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-t-next");
        WOTSPlus.WinternitzAddress[] memory keys = _mkKeys(0x2000, 2);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Transaction,
            false,
            currentKey,
            currentPriv,
            next,
            keys
        );

        uint256 before_ = harnessProxy.keyCount(Codec.KeyType.Transaction);
        harnessProxy.exposed_manageKeys(payload, false);

        // +2 appended, -1/+1 rotation ⇒ net +2.
        assertEq(
            harnessProxy.keyCount(Codec.KeyType.Transaction),
            before_ + 2
        );
    }

    function test_exposed_manageKeys_add_emitsKeysAdded() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-v-next-ev");
        WOTSPlus.WinternitzAddress[] memory keys = _mkKeys(0x3000, 3);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            false,
            currentKey,
            currentPriv,
            next,
            keys
        );

        vm.recordLogs();
        harnessProxy.exposed_manageKeys(payload, false);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 expected = IQuipWallet.KeysAdded.selector;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == expected) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysAdded not emitted");
    }

    /*──────────────────────── refresh (replace=true) ────────────────────────*/

    function test_exposed_manageKeys_refresh_verification_clearsAndReplaces()
        public
    {
        // Pre-seed verification set with a dummy element so we can observe clearing.
        {
            (
                WOTSPlus.WinternitzAddress memory nextSeed,

            ) = _generateKeyPair("h-mk-pre-seed");
            WOTSPlus.WinternitzAddress[] memory seed = _mkKeys(0x4000, 1);
            bytes memory seedPayload = _encodePayload(
                Codec.KeyType.Verification,
                false,
                currentKey,
                currentPriv,
                nextSeed,
                seed
            );
            harnessProxy.exposed_manageKeys(seedPayload, false);
            // Rotate tracked currentKey / currentPriv so downstream signatures are fresh.
            currentKey = nextSeed;
            currentPriv = _privFor("h-mk-pre-seed");
        }

        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-refresh-next");
        WOTSPlus.WinternitzAddress[] memory fresh = _mkKeys(0x5000, 2);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            true,
            currentKey,
            currentPriv,
            next,
            fresh
        );

        harnessProxy.exposed_manageKeys(payload, true);

        assertEq(harnessProxy.keyCount(Codec.KeyType.Verification), 2);
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, fresh[0]));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Verification, fresh[1]));
    }

    function test_exposed_manageKeys_refresh_emitsKeysRefreshed() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-refresh-ev");
        WOTSPlus.WinternitzAddress[] memory fresh = _mkKeys(0x6000, 1);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            true,
            currentKey,
            currentPriv,
            next,
            fresh
        );

        vm.recordLogs();
        harnessProxy.exposed_manageKeys(payload, true);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 expected = IQuipWallet.KeysRefreshed.selector;
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == expected) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysRefreshed not emitted");
    }

    /*──────────────────────────── reverts ──────────────────────────────*/

    function test_exposed_manageKeys_revertsWhen_refreshTransaction() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-rt-next");
        WOTSPlus.WinternitzAddress[] memory keys = _mkKeys(0x7000, 1);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Transaction,
            true,
            currentKey,
            currentPriv,
            next,
            keys
        );

        vm.expectRevert(IQuipWallet.RefreshTransactionForbidden.selector);
        harnessProxy.exposed_manageKeys(payload, true);
    }

    function test_exposed_manageKeys_revertsWhen_emptyKeys_addVerification()
        public
    {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-ek-v");
        WOTSPlus.WinternitzAddress[] memory empty;
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            false,
            currentKey,
            currentPriv,
            next,
            empty
        );

        vm.expectRevert(IQuipWallet.EmptyKeys.selector);
        harnessProxy.exposed_manageKeys(payload, false);
    }

    function test_exposed_manageKeys_revertsWhen_emptyKeys_refreshRecovery()
        public
    {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-ek-r");
        WOTSPlus.WinternitzAddress[] memory empty;
        bytes memory payload = _encodePayload(
            Codec.KeyType.Recovery,
            true,
            currentKey,
            currentPriv,
            next,
            empty
        );

        vm.expectRevert(IQuipWallet.EmptyKeys.selector);
        harnessProxy.exposed_manageKeys(payload, true);
    }

    function test_exposed_manageKeys_revertsWhen_authCurrentAbsent() public {
        (
            WOTSPlus.WinternitzAddress memory stray,
            bytes32 strayPriv
        ) = _generateKeyPair("h-mk-auth-stray");
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-auth-next");
        WOTSPlus.WinternitzAddress[] memory keys = _mkKeys(0x8000, 1);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            false,
            stray,
            strayPriv,
            next,
            keys
        );

        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        harnessProxy.exposed_manageKeys(payload, false);
    }

    function test_exposed_manageKeys_revertsWhen_signatureInvalid() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-sig-next");
        WOTSPlus.WinternitzAddress[] memory keys = _mkKeys(0x9000, 1);

        // Sign a digest for a DIFFERENT payload so verification fails on the encoded one.
        WOTSPlus.WinternitzElements memory badSig = _sign(
            currentPriv,
            keccak256("not-the-real-digest")
        );
        bytes memory payload = Codec.encodeKeyManagement(
            Codec.KeyType.Verification,
            currentKey,
            next,
            badSig,
            keys
        );

        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        harnessProxy.exposed_manageKeys(payload, false);
    }

    function test_exposed_manageKeys_revertsWhen_newKeyInUse() public {
        (
            WOTSPlus.WinternitzAddress memory next,

        ) = _generateKeyPair("h-mk-dup-next");
        WOTSPlus.WinternitzAddress[]
            memory dup = new WOTSPlus.WinternitzAddress[](2);
        dup[0] = _mkKey(0xa000);
        dup[1] = _mkKey(0xa000);
        bytes memory payload = _encodePayload(
            Codec.KeyType.Verification,
            false,
            currentKey,
            currentPriv,
            next,
            dup
        );

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        harnessProxy.exposed_manageKeys(payload, false);
    }

    function _privFor(bytes32 seed) internal pure returns (bytes32) {
        (, bytes32 priv) = WOTSPlus.generateKeyPair(seed);
        return priv;
    }
}
