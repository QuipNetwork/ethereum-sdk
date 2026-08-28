// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeUpgradeToAndCall is WOTSPlusCodecTest {
    struct UpgradeBundle {
        WOTSPlus.WinternitzAddress cur;
        WOTSPlus.WinternitzAddress nxt;
        WOTSPlus.WinternitzElements pqSig;
        WOTSPlus.WinternitzAddress verifier;
        WOTSPlus.WinternitzElements verifySig;
        bool shouldMigrate;
        bytes migrator;
    }

    function _samplePair()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory cur, WOTSPlus.WinternitzAddress memory nxt)
    {
        cur = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        nxt = WOTSPlus.WinternitzAddress(bytes32(uint256(3)), bytes32(uint256(4)));
    }

    function _sampleUpgradeBundle(bool shouldMigrate) internal pure returns (UpgradeBundle memory b) {
        (b.cur, b.nxt) = _samplePair();
        b.shouldMigrate = shouldMigrate;
        b.migrator = new bytes(2048);
    }

    function _encodeUpgrade(UpgradeBundle memory b) internal view returns (bytes memory) {
        return codec.exposed_encodeUpgradeToAndCall(
            b.cur, b.nxt, b.pqSig, b.verifier, b.verifySig, b.shouldMigrate, b.migrator
        );
    }

    function test_exposed_encodeUpgradeToAndCall_producesCorrectLengthMigrateTrue() public view {
        bytes memory encoded = _encodeUpgrade(_sampleUpgradeBundle(true));
        // 64 + 64 + 2144 + 64 + 2144 + 1 + 2048 = 6529
        assertEq(encoded.length, 6529);
    }

    function test_exposed_encodeUpgradeToAndCall_producesCorrectLengthMigrateFalse() public view {
        bytes memory encoded = _encodeUpgrade(_sampleUpgradeBundle(false));
        assertEq(encoded.length, 6529);
        // shouldMigrate byte at offset 4480 must be 0x00.
        assertEq(uint8(encoded[4480]), 0);
    }

    function test_exposed_encodeUpgradeToAndCall_migrateTrueByte() public view {
        bytes memory encoded = _encodeUpgrade(_sampleUpgradeBundle(true));
        assertEq(uint8(encoded[4480]), 1);
    }

    function test_exposed_encodeUpgradeToAndCall_roundtripsAuth() public view {
        UpgradeBundle memory b = _sampleUpgradeBundle(true);
        b.verifier = WOTSPlus.WinternitzAddress(bytes32(uint256(50)), bytes32(uint256(51)));
        for (uint256 i = 0; i < 67; i++) {
            b.pqSig.elements[i] = bytes32(i + 1000);
        }
        for (uint256 i = 0; i < 67; i++) {
            b.verifySig.elements[i] = bytes32(i + 3000);
        }
        bytes memory encoded = _encodeUpgrade(b);
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig
        ) = codec.exposed_decodeUpgradeAuth(encoded);

        assertEq(dCur.publicSeed, b.cur.publicSeed);
        assertEq(dNxt.publicSeed, b.nxt.publicSeed);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], b.pqSig.elements[i]);
        }
    }

    function test_exposed_encodeUpgradeToAndCall_roundtripsMigration() public view {
        UpgradeBundle memory b = _sampleUpgradeBundle(true);
        b.migrator = _buildInitPayload(99);
        bytes memory encoded = _encodeUpgrade(b);
        (bool shouldMigrate, bytes memory dMigrator) = codec.exposed_decodeUpgradeMigration(encoded);

        assertTrue(shouldMigrate);
        assertEq(dMigrator.length, 2048);
        assertEq(dMigrator, b.migrator);
    }

    function _fuzzUpgradeBundle(bytes32 seed, bool shouldMigrate) internal view returns (UpgradeBundle memory b) {
        b.cur = _fuzzWinternitzAddress(seed, 0);
        b.nxt = _fuzzWinternitzAddress(seed, 1);
        b.pqSig = _fuzzWinternitzElements(seed);
        b.verifier = _fuzzWinternitzAddress(seed, 2);
        b.verifySig = _fuzzWinternitzElementsAlt(seed);
        b.shouldMigrate = shouldMigrate;
        b.migrator = codec.exposed_encodeInit(
            _fuzzWinternitzAddress(seed, 100),
            _fuzzWinternitzAddress(seed, 101),
            _fuzzTransactionKeys(bytes32(uint256(seed) ^ 0xDEAD)),
            _fuzzRecoveryKeys(bytes32(uint256(seed) ^ 0xBEEF)),
            _fuzzVerificationKeys(bytes32(uint256(seed) ^ 0xCAFE))
        );
    }

    function _assertUpgradeAuth(UpgradeBundle memory b, bytes memory encoded) internal view {
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dPqSig
        ) = codec.exposed_decodeUpgradeAuth(encoded);
        assertEq(dCur.publicSeed, b.cur.publicSeed);
        assertEq(dCur.publicKeyHash, b.cur.publicKeyHash);
        assertEq(dNxt.publicSeed, b.nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, b.nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dPqSig.elements[i], b.pqSig.elements[i]);
        }
    }

    function _assertUpgradeVerification(UpgradeBundle memory b, bytes memory encoded) internal view {
        (WOTSPlus.WinternitzAddress memory dVerifier, WOTSPlus.WinternitzElements memory dVerifySig) =
            codec.exposed_decodeUpgradeVerification(encoded);
        assertEq(dVerifier.publicSeed, b.verifier.publicSeed);
        assertEq(dVerifier.publicKeyHash, b.verifier.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dVerifySig.elements[i], b.verifySig.elements[i]);
        }
    }

    function _assertUpgradeMigration(UpgradeBundle memory b, bytes memory encoded) internal view {
        (bool dShouldMigrate, bytes memory dMigrator) = codec.exposed_decodeUpgradeMigration(encoded);
        assertEq(dShouldMigrate, b.shouldMigrate);
        assertEq(dMigrator.length, 2048);
        assertEq(dMigrator, b.migrator);
    }

    /// @dev Property: encode → decode preserves every field for any seed and
    ///      `shouldMigrate` flag, across all three decoders that consume the
    ///      shared 6529-byte upgrade payload (auth + verification + migration).
    ///      Migrator payload is fixed at 2048 bytes — decodeUpgradeMigration
    ///      slices a fixed-width [4481:6529) range, so any other size breaks
    ///      the total length and would not roundtrip.
    function testFuzz_exposed_encodeUpgradeToAndCall_roundtrips(bytes32 seed, bool shouldMigrate) public view {
        UpgradeBundle memory b = _fuzzUpgradeBundle(seed, shouldMigrate);
        bytes memory encoded = _encodeUpgrade(b);
        assertEq(encoded.length, 6529);
        _assertUpgradeAuth(b, encoded);
        _assertUpgradeVerification(b, encoded);
        _assertUpgradeMigration(b, encoded);
    }
}
