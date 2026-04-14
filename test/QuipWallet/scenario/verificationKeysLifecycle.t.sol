// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_scenario_verificationKeysLifecycle is QuipWalletTest {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;

    WOTSPlus.WinternitzAddress[] internal seededKeys;
    bytes32[] internal seededPriv;
    WOTSPlus.WinternitzAddress internal replacement;
    WOTSPlus.WinternitzAddress[] internal freshKeys;

    bytes32 internal initialPqSeed;
    bytes32 internal initialPqHash;

    function _step1_assertEmptyRejectsAll() internal {
        assertEq(wallet.getVerificationKeyCount(), 0);
        assertEq(wallet.isValidSignature(keccak256("hi"), new bytes(2208)), FAIL);
        (initialPqSeed, initialPqHash) = wallet.pqOwner();
    }

    function _step2_seedThreeKeys() internal {
        (WOTSPlus.WinternitzAddress[] memory k, bytes32[] memory p) =
            _seedVerificationKeys(3);
        for (uint256 i = 0; i < k.length; i++) {
            seededKeys.push(k[i]);
            seededPriv.push(p[i]);
        }
        assertEq(wallet.getVerificationKeyCount(), 3);
        (bytes32 s, bytes32 h) = wallet.pqOwner();
        assertTrue(s != initialPqSeed || h != initialPqHash, "pqOwner not rotated");
    }

    function _step3_signWithEachKey() internal {
        for (uint256 i = 0; i < seededKeys.length; i++) {
            bytes32 msgHash = keccak256(abi.encodePacked("msg", i));
            bytes32 digest = _buildErc1271MessageHash(address(wallet), seededKeys[i], msgHash);
            WOTSPlus.WinternitzElements memory sig = _sign(seededPriv[i], digest);
            assertEq(
                wallet.isValidSignature(
                    msgHash, Codec.encodeErc1271Signature(seededKeys[i], sig)
                ),
                MAGIC
            );
        }
        assertEq(wallet.getVerificationKeyCount(), 3);
    }

    function _step4_replaceIndex1() internal {
        WOTSPlus.WinternitzAddress memory oldKey = wallet.getVerificationKeyAt(1);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("lifecycle-replace");
        replacement = newKey;

        (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextKey) =
            _generateKeyPair("lifecycle-next-2");
        bytes32 digest = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 1, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, digest);

        vm.prank(ALICE);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 1, newKey)
        );
        alicePubkey = nextPq;
        alicePrivateKey = nextKey;

        assertFalse(wallet.isVerificationKey(oldKey));
        assertTrue(wallet.isVerificationKey(newKey));
        assertEq(wallet.getVerificationKeyCount(), 3);
    }

    function _step5_refreshWithFiveKeys() internal {
        for (uint256 i = 0; i < 5; i++) {
            (WOTSPlus.WinternitzAddress memory k,) =
                _generateKeyPair(keccak256(abi.encodePacked("lifecycle-fresh", i)));
            freshKeys.push(k);
        }

        (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextKey) =
            _generateKeyPair("lifecycle-next-3");
        bytes32 digest = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, freshKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, digest);

        vm.prank(ALICE);
        wallet.refreshVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, freshKeys));
        alicePubkey = nextPq;
        alicePrivateKey = nextKey;

        assertEq(wallet.getVerificationKeyCount(), 5);
    }

    function _step6_finalAssertions() internal view {
        // Every original seeded key must be gone.
        for (uint256 i = 0; i < seededKeys.length; i++) {
            assertFalse(wallet.isVerificationKey(seededKeys[i]));
        }
        // Replacement from step 4 should also be gone after refresh.
        assertFalse(wallet.isVerificationKey(replacement));
        // All fresh keys present.
        for (uint256 i = 0; i < freshKeys.length; i++) {
            assertTrue(wallet.isVerificationKey(freshKeys[i]));
        }
        // Final pqOwner must differ from the initial one.
        (bytes32 s, bytes32 h) = wallet.pqOwner();
        assertTrue(s != initialPqSeed || h != initialPqHash, "final pqOwner equals initial");
    }

    function test_simulation_verificationKeysLifecycle() public {
        _step1_assertEmptyRejectsAll();
        _step2_seedThreeKeys();
        _step3_signWithEachKey();
        _step4_replaceIndex1();
        _step5_refreshWithFiveKeys();
        _step6_finalAssertions();
    }
}
