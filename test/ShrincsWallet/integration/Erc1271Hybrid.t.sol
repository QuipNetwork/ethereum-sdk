// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.4.0/test/helpers/SHRINCSTestSigner.sol";
import {SignatureChecker} from "@openzeppelin-contracts-5.6.0-rc.1/utils/cryptography/SignatureChecker.sol";
import {SignatureCheckerLib} from "solady-0.1.26/src/utils/SignatureCheckerLib.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {IERC1271} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/IERC1271.sol";

/// @dev A minimal relying protocol: it settles an order once the order's `signer` approves the
///      order hash. The check goes through the two signature-checker libraries protocols use in
///      practice (OpenZeppelin and Solady), which both STATICCALL `isValidSignature` on a
///      contract signer. The protocol knows nothing about SHRINCS.
contract Erc1271RelyingProtocol {
    error OrderNotApproved();
    error OrderAlreadySettled();

    event OrderSettled(address indexed signer, bytes32 indexed orderHash);

    mapping(bytes32 orderHash => bool) public settled;

    function settleWithOpenZeppelin(address signer, bytes32 orderHash, bytes calldata signature) external {
        if (!SignatureChecker.isValidSignatureNowCalldata(signer, orderHash, signature)) revert OrderNotApproved();
        _settle(signer, orderHash);
    }

    function settleWithSolady(address signer, bytes32 orderHash, bytes calldata signature) external {
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(signer, orderHash, signature)) revert OrderNotApproved();
        _settle(signer, orderHash);
    }

    function _settle(address signer, bytes32 orderHash) internal {
        if (settled[orderHash]) revert OrderAlreadySettled();
        settled[orderHash] = true;
        emit OrderSettled(signer, orderHash);
    }
}

/// @title Hybrid ERC-1271, end to end
/// @dev The wallet is deployed through the real `WalletFactory` against the real hashsigs 0.4.0
///      verifier pair (base fixture). Every test drives the hybrid signature — owner ECDSA AND
///      the dedicated key's stateless SHRINCS signature, in the fixed-layout envelope — through
///      an external relying contract, never by calling the wallet directly.
///
///      The last section pins the transport budget QUI-1328 exists for: the envelope must fit a
///      WalletConnect relay message once hex-encoded, encrypted and base64-encoded.
contract ShrincsWallet_Erc1271Hybrid is ShrincsWalletTest {
    bytes32 internal constant ORDER = keccak256("hybrid-erc1271-order");

    /// @dev WalletConnect relay publish cap in bytes, as recorded in QUI-1328 (104 KiB).
    uint256 internal constant WC_RELAY_MESSAGE_CAP = 106_496;
    /// @dev WalletConnect type-0 envelope overhead around the plaintext: 1 type byte, 12-byte IV
    ///      and the 16-byte ChaCha20-Poly1305 tag.
    uint256 internal constant WC_ENVELOPE_OVERHEAD = 1 + 12 + 16;

    Erc1271RelyingProtocol internal protocol;

    function setUp() public override {
        super.setUp();
        protocol = new Erc1271RelyingProtocol();
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertFalse(protocol.settled(ORDER), "order starts unsettled");
        assertTrue(WALLET.code.length != 0, "signer is a contract: checkers take the ERC-1271 path");
    }

    /* ───────────────────────────── relying-contract flow ───────────────────────────── */

    function test_hybridErc1271_settlesThroughOpenZeppelinChecker() public {
        bytes memory signature = _erc1271Blob(ORDER);
        assertEq(signature.length, Codec.ERC1271_TOTAL_LEN, "fixed-layout envelope");
        vm.expectEmit(address(protocol));
        emit Erc1271RelyingProtocol.OrderSettled(WALLET, ORDER);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, signature);
        assertTrue(protocol.settled(ORDER), "order settled");
    }

    function test_hybridErc1271_settlesThroughSoladyChecker() public {
        bytes memory signature = _erc1271Blob(ORDER);
        protocol.settleWithSolady(WALLET, ORDER, signature);
        assertTrue(protocol.settled(ORDER), "order settled");
    }

    /// @dev Validation consumes nothing: the same signature answers any number of checks while
    ///      the wallet's signing context is unchanged.
    function test_hybridErc1271_validationIsViewAndRepeatable() public {
        bytes memory signature = _erc1271Blob(ORDER);
        uint256 nonceBefore = wallet.actionNonce();
        uint256 leavesBefore = wallet.statefulLeavesUsed();
        for (uint256 i; i < 3; ++i) {
            assertEq(wallet.isValidSignature(ORDER, signature), IERC1271.isValidSignature.selector, "magic value");
        }
        protocol.settleWithOpenZeppelin(WALLET, ORDER, signature);
        assertEq(wallet.actionNonce(), nonceBefore, "no nonce consumed");
        assertEq(wallet.statefulLeavesUsed(), leavesBefore, "no stateful leaf consumed");
    }

    /// @dev The wallet's cost inside a relying contract's STATICCALL, with the calldata cost of
    ///      carrying the envelope reported alongside.
    function test_hybridErc1271_gasInsideRelyingCall() public {
        bytes memory signature = _erc1271Blob(ORDER);
        uint256 gasBefore = gasleft();
        protocol.settleWithOpenZeppelin(WALLET, ORDER, signature);
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("settle (execution, incl. isValidSignature)", used);
        emit log_named_uint("envelope calldata gas", _calldataGas(signature));
        // Loose ceiling: catches an accidental return to quadratic memory or a second verify.
        assertLt(used, 3_000_000, "hybrid ERC-1271 settle stays under 3M gas");
    }

    /* ───────────────────────────── lifecycle ───────────────────────────── */

    /// @dev Sign → the wallet consumes an unrelated signed action (nonce advances) → the
    ///      outstanding approval is dead → a fresh signature over the same order settles.
    function test_hybridErc1271_supersededByWalletAction_thenResigned() public {
        bytes memory stale = _erc1271Blob(ORDER);

        bytes32 userOpHash = keccak256("hybrid-intervening-userop");
        bytes memory opSig = _userOpBlob(_signErc4337(userOpHash, 1), userOpHash);
        vm.prank(ENTRY_POINT);
        assertEq(wallet.validateUserOp(_makeUserOp(opSig), userOpHash, 0), 0, "intervening userOp validated");

        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, stale);
        assertFalse(protocol.settled(ORDER), "stale approval did not settle");

        protocol.settleWithOpenZeppelin(WALLET, ORDER, _erc1271Blob(ORDER));
        assertTrue(protocol.settled(ORDER), "fresh approval settles");
    }

    /// @dev Rotating the dedicated ERC-1271 key: signatures by the retired key stop working and
    ///      the new key's signatures settle.
    function test_hybridErc1271_followsDedicatedKeyRotation() public {
        (SHRINCS.SigningKey memory newKey, SHRINCS.PublicKey memory newPk, bool ok) =
            SHRINCSTestSigner.keygen("hybrid-rotated-erc1271", MAX_SIG);
        assertTrue(ok, "new erc1271 keygen");
        SHRINCS.Signature memory auth = _signStatefulAction(
            Codec.ACTION_SET_ERC1271_KEY,
            Codec.setErc1271KeyPayloadHash(_commitment32(newPk), HashSuite.HASH_SUITE_ID),
            1
        );
        vm.prank(OWNER);
        wallet.setErc1271Key(_mainPk(), auth, newPk, HashSuite.HASH_SUITE_ID);
        assertEq(wallet.getErc1271PublicKeyCommitment(), _commitment32(newPk), "new key installed");

        // Retired key, signing against the LIVE context (new commitment, new nonce).
        bytes memory retired = _erc1271Envelope(
            erc1271Pk, _signStatelessRaw(erc1271Key, erc1271Pk, _erc1271Message(ORDER)), _ownerEcdsa(ORDER)
        );
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, retired);

        bytes memory current =
            _erc1271Envelope(newPk, _signStatelessRaw(newKey, newPk, _erc1271Message(ORDER)), _ownerEcdsa(ORDER));
        protocol.settleWithOpenZeppelin(WALLET, ORDER, current);
        assertTrue(protocol.settled(ORDER), "new key's approval settles");
    }

    /* ───────────────────────────── WalletConnect transport budget ───────────────────────────── */

    /// @dev One hybrid signature, returned by the wallet app as the result of a signing request,
    ///      fits a WalletConnect relay message with room to spare.
    function test_hybridErc1271_fitsWalletConnectRelayMessage() public {
        bytes memory signature = _erc1271Blob(ORDER);
        uint256 wire = _walletConnectMessageLen(signature.length);
        emit log_named_uint("signature bytes", signature.length);
        emit log_named_uint("JSON-RPC result, hex chars", _hexLen(signature.length));
        emit log_named_uint("relay message bytes (encrypted, base64)", wire);
        emit log_named_uint("relay cap bytes", WC_RELAY_MESSAGE_CAP);
        assertEq(signature.length, Codec.ERC1271_TOTAL_LEN, "exact envelope length");
        assertLt(wire, WC_RELAY_MESSAGE_CAP, "one signature fits the relay cap");
        assertLt(wire * 100, WC_RELAY_MESSAGE_CAP * 80, "at least 20% headroom");
    }

    /// @dev The reason for the fixed layout: the pre-0.4.0 ABI signature did not fit.
    function test_hybridErc1271_legacyAbiSignatureExceedsWalletConnectRelayMessage() public pure {
        assertGt(_walletConnectMessageLen(LEGACY_ERC1271_ABI_LEN), WC_RELAY_MESSAGE_CAP, "legacy does not fit");
    }

    /// @dev Known limit, pinned so it is not rediscovered in production: TWO hybrid signatures in
    ///      one message (e.g. a 2-of-2 Safe `signatures` blob with both owners Quip wallets, sent
    ///      as a single request) do not fit. Each signature must travel in its own message.
    function test_hybridErc1271_twoSignaturesInOneMessageExceedWalletConnectRelayMessage() public pure {
        assertGt(_walletConnectMessageLen(2 * Codec.ERC1271_TOTAL_LEN), WC_RELAY_MESSAGE_CAP, "two do not fit");
    }

    /* ───────────────────────────── rejections (the relying protocol reverts) ───────────────────────────── */

    /// @dev Valid stateless SHRINCS half, ECDSA half from a key that is not `owner()`.
    function test_hybridErc1271_revertsWhen_ecdsaHalfNotOwner() public {
        (, uint256 strangerKey) = makeAddrAndKey("hybrid-stranger");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(strangerKey, wallet.quipSignedHashEcdsaTarget(ORDER));
        bytes memory signature = _erc1271Envelope(erc1271Pk, _signErc1271(ORDER), abi.encodePacked(r, s, v));
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, signature);
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithSolady(WALLET, ORDER, signature);
    }

    /// @dev Valid owner ECDSA half, all-zero stateless half: the classical key alone is not enough.
    function test_hybridErc1271_revertsWhen_shrincsHalfMissing() public {
        bytes memory signature = _erc1271Envelope(erc1271Pk, new bytes(StatelessLayout.PQ_LEN), _ownerEcdsa(ORDER));
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, signature);
    }

    /// @dev Valid owner ECDSA half, stateless half signed by the wallet's MAIN key instead of the
    ///      dedicated ERC-1271 key: key isolation holds through the relying contract.
    function test_hybridErc1271_revertsWhen_shrincsHalfFromMainKey() public {
        SHRINCS.ActionContext memory ctx = _actionContext(Codec.ACTION_ERC1271, ORDER);
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessRawMessageHash(mainCommitment, SHRINCS.statelessActionMessageHash(mainCommitment, ctx))
        );
        bytes memory signature =
            _erc1271Envelope(mainPk, _signStatelessRaw(mainKey, mainPk, message), _ownerEcdsa(ORDER));
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, signature);
    }

    /// @dev A signature approves exactly one hash.
    function test_hybridErc1271_revertsWhen_presentedForOtherOrder() public {
        bytes memory signature = _erc1271Blob(ORDER);
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, keccak256("some-other-order"), signature);
    }

    /// @dev The pre-0.4.0 ABI-encoded signature is refused; the relying contract sees an ordinary
    ///      "not approved", not a revert from inside the wallet.
    function test_hybridErc1271_revertsWhen_legacyAbiSignature() public {
        bytes memory legacy = _legacyErc1271Blob(ORDER);
        assertEq(legacy.length, LEGACY_ERC1271_ABI_LEN, "legacy 256s ABI signature size");
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, legacy);
    }

    /// @dev Arbitrary bytes never make the wallet revert inside the relying contract's call.
    function test_hybridErc1271_revertsWhen_garbageSignature() public {
        bytes memory garbage = new bytes(Codec.ERC1271_TOTAL_LEN);
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithOpenZeppelin(WALLET, ORDER, garbage);
        vm.expectRevert(Erc1271RelyingProtocol.OrderNotApproved.selector);
        protocol.settleWithSolady(WALLET, ORDER, hex"deadbeef");
    }

    /* ───────────────────────────────── helpers ───────────────────────────────── */

    /// @dev `0x` + two hex characters per byte.
    function _hexLen(uint256 byteLen) internal pure returns (uint256) {
        return 2 + 2 * byteLen;
    }

    /// @dev Size of the relay message carrying `byteLen` bytes as a JSON-RPC result:
    ///      `{"id":<16 digits>,"jsonrpc":"2.0","result":"0x…"}` → WalletConnect type-0 envelope
    ///      (type ‖ IV ‖ ciphertext ‖ tag) → base64.
    function _walletConnectMessageLen(uint256 byteLen) internal pure returns (uint256) {
        uint256 jsonLen = bytes('{"id":1700000000000000,"jsonrpc":"2.0","result":""}').length + _hexLen(byteLen);
        uint256 sealedLen = WC_ENVELOPE_OVERHEAD + jsonLen;
        return 4 * ((sealedLen + 2) / 3);
    }
}
