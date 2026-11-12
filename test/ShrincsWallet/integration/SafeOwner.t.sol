// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.4.0/test/helpers/SHRINCSTestSigner.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {Safe150Bytecode as SafeCode} from "./Safe150Bytecode.sol";
import {ISafe150, ISafeProxyFactory150, ICompatibilityFallbackHandler150} from "./ISafe150.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {IERC1271} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/IERC1271.sol";

/// @title ShrincsWallet as a Safe v1.5.0 owner
/// @dev The wallet's fixed-layout ERC-1271 envelope driven through the REAL Safe v1.5.0 deployment:
///      canonical runtime bytecode etched at the canonical addresses (code hashes asserted against
///      safe-deployments), Safes created by the real `SafeProxyFactory`. Each Quip owner signs the
///      raw `safeTxHash` / SafeMessage hash directly (no personal-sign prefix) and appears in
///      Safe's signature blob as a v=0 contract signature: static part `r = owner, s = offset,
///      v = 0`, dynamic part `len || envelope`, owners sorted ascending.
contract ShrincsWallet_SafeOwner is ShrincsWalletTest {
    /// @dev A Quip wallet plus everything needed to produce its ERC-1271 signatures.
    struct QuipOwner {
        ShrincsWalletHarness wallet;
        SHRINCS.SigningKey erc1271Key;
        SHRINCS.PublicKey erc1271Pk;
        bytes32 erc1271Commitment;
        uint256 ownerKey;
    }

    /// @dev One Safe owner's signature: contract (v=0, dynamic) or EOA ECDSA (static only).
    struct SafeSig {
        address owner;
        bool isContract;
        bytes data;
    }

    uint256 internal constant SEND_VALUE = 1 ether;
    uint256 internal constant SAFE_FUNDS = 10 ether;

    QuipOwner internal quipA;
    QuipOwner internal quipB;
    address internal EOA_OWNER;
    uint256 internal EOA_OWNER_KEY;
    address internal RECIPIENT;

    ISafe150 internal safe1of1;
    ISafe150 internal safe1of2;
    ISafe150 internal safe2of2;

    function setUp() public override {
        super.setUp();
        vm.etch(SafeCode.SAFE_ADDRESS, SafeCode.SAFE_RUNTIME);
        vm.etch(SafeCode.PROXY_FACTORY_ADDRESS, SafeCode.PROXY_FACTORY_RUNTIME);
        vm.etch(SafeCode.FALLBACK_HANDLER_ADDRESS, SafeCode.FALLBACK_HANDLER_RUNTIME);

        (EOA_OWNER, EOA_OWNER_KEY) = makeAddrAndKey("safeEoaOwner");
        RECIPIENT = makeAddr("safeRecipient");

        quipA = QuipOwner(wallet, erc1271Key, erc1271Pk, erc1271Commitment, OWNER_PK);
        quipB = _deploySecondQuipWallet();

        safe1of1 = _deploySafe(_owners1(address(quipA.wallet)), 1, 1);
        safe1of2 = _deploySafe(_owners2(address(quipA.wallet), EOA_OWNER), 1, 2);
        safe2of2 = _deploySafe(_owners2(address(quipA.wallet), address(quipB.wallet)), 2, 3);
        vm.deal(address(safe1of1), SAFE_FUNDS);
        vm.deal(address(safe1of2), SAFE_FUNDS);
        vm.deal(address(safe2of2), SAFE_FUNDS);
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertEq(SafeCode.SAFE_ADDRESS.codehash, SafeCode.SAFE_CODEHASH, "Safe 1.5.0 canonical code");
        assertEq(SafeCode.PROXY_FACTORY_ADDRESS.codehash, SafeCode.PROXY_FACTORY_CODEHASH, "factory canonical code");
        assertEq(
            SafeCode.FALLBACK_HANDLER_ADDRESS.codehash, SafeCode.FALLBACK_HANDLER_CODEHASH, "handler canonical code"
        );
        assertEq(safe1of1.getThreshold(), 1);
        assertEq(safe1of1.getOwners().length, 1);
        assertEq(safe1of2.getThreshold(), 1);
        assertEq(safe1of2.getOwners().length, 2);
        assertEq(safe2of2.getThreshold(), 2);
        assertEq(safe2of2.getOwners().length, 2);
        assertTrue(address(quipB.wallet) != address(quipA.wallet), "two distinct Quip wallets");
        assertEq(quipB.wallet.getErc1271PublicKeyCommitment(), quipB.erc1271Commitment);
        assertEq(address(safe1of1).balance, SAFE_FUNDS);
    }

    /* ─────────────────────────────── execTransaction ─────────────────────────────── */

    function test_safeOwner_execTransaction_oneOfOneQuip() public {
        bytes32 txHash = _txHash(safe1of1);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipA, txHash);
        _execAndReport(safe1of1, _buildSafeSignatures(sigs), "execTransaction gas, 1-of-1 (one Quip owner)");
    }

    function test_safeOwner_execTransaction_oneOfTwoQuipAndEoa() public {
        bytes32 txHash = _txHash(safe1of2);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipA, txHash);
        _execAndReport(safe1of2, _buildSafeSignatures(sigs), "execTransaction gas, 1-of-2 (Quip signs, EOA idle)");
    }

    /// @dev Mixed static + dynamic parts: the EOA's 65-byte ECDSA sits beside the Quip v=0 entry.
    function test_safeOwner_execTransaction_twoOfTwoQuipAndEoa_mixedSignatures() public {
        ISafe150 mixed = _deploySafe(_owners2(address(quipA.wallet), EOA_OWNER), 2, 4);
        vm.deal(address(mixed), SAFE_FUNDS);
        bytes32 txHash = _txHash(mixed);
        SafeSig[] memory sigs = new SafeSig[](2);
        sigs[0] = _quipSig(quipA, txHash);
        sigs[1] = _eoaSig(EOA_OWNER_KEY, txHash);
        _execAndReport(mixed, _buildSafeSignatures(sigs), "execTransaction gas, 2-of-2 (Quip + EOA)");
    }

    function test_safeOwner_execTransaction_twoOfTwoQuip() public {
        bytes32 txHash = _txHash(safe2of2);
        SafeSig[] memory sigs = new SafeSig[](2);
        sigs[0] = _quipSig(quipA, txHash);
        sigs[1] = _quipSig(quipB, txHash);
        _execAndReport(safe2of2, _buildSafeSignatures(sigs), "execTransaction gas, 2-of-2 (two Quip owners)");
    }

    function test_safeOwner_checkSignatures_oneOfOneQuip() public {
        bytes32 txHash = _txHash(safe1of1);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipA, txHash);
        safe1of1.checkSignatures(address(0), txHash, _buildSafeSignatures(sigs));
    }

    function test_safeOwner_checkSignatures_twoOfTwoQuip() public {
        bytes32 txHash = _txHash(safe2of2);
        SafeSig[] memory sigs = new SafeSig[](2);
        sigs[0] = _quipSig(quipA, txHash);
        sigs[1] = _quipSig(quipB, txHash);
        safe2of2.checkSignatures(address(0), txHash, _buildSafeSignatures(sigs));
    }

    /* ─────────────────────────── nested: SafeMessage ERC-1271 ─────────────────────────── */

    /// @dev The Safe ITSELF answering ERC-1271 through its fallback handler: the Quip owner signs
    ///      the SafeMessage hash, and the handler's `checkSignatures` reaches the Quip wallet's
    ///      `isValidSignature` over that hash.
    function test_safeOwner_fallbackIsValidSignature_safeMessage() public {
        bytes32 appHash = keccak256("dapp-message-for-the-safe");
        bytes32 safeMessageHash = ICompatibilityFallbackHandler150(address(safe1of1)).getMessageHashForSafe(
            address(safe1of1), abi.encode(appHash)
        );
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipA, safeMessageHash);
        assertEq(
            ICompatibilityFallbackHandler150(address(safe1of1)).isValidSignature(appHash, _buildSafeSignatures(sigs)),
            IERC1271.isValidSignature.selector
        );
    }

    /* ─────────────────────────────────── reverts ─────────────────────────────────── */

    function test_safeOwner_execTransaction_revertsWhen_tamperedQuipSignature() public {
        bytes32 txHash = _txHash(safe1of1);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipA, txHash);
        // Flip one FORS byte deep inside the envelope.
        sigs[0].data[Codec.ERC1271_PAYLOAD_OFF + StatelessLayout.PK_LEN + 100] ^= 0x01;
        bytes memory signatures = _buildSafeSignatures(sigs);
        vm.expectRevert(bytes("GS024"));
        _exec(safe1of1, signatures);
    }

    /// @dev Below threshold: the lone v=0 entry's offset (65) points inside the 2 × 65-byte static
    ///      region Safe expects at threshold 2, so Safe rejects it as GS021 before any ERC-1271 call.
    function test_safeOwner_execTransaction_revertsWhen_oneOfTwoQuipSignatures() public {
        bytes32 txHash = _txHash(safe2of2);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipA, txHash);
        bytes memory signatures = _buildSafeSignatures(sigs);
        vm.expectRevert(bytes("GS021"));
        _exec(safe2of2, signatures);
    }

    /// @dev Quip B's envelope presented under Quip A's address: A's key/owner do not sign it.
    function test_safeOwner_checkSignatures_revertsWhen_signatureFromOtherQuipWallet() public {
        bytes32 txHash = _txHash(safe1of1);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = _quipSig(quipB, txHash);
        sigs[0].owner = address(quipA.wallet);
        bytes memory signatures = _buildSafeSignatures(sigs);
        vm.expectRevert(bytes("GS024"));
        safe1of1.checkSignatures(address(0), txHash, signatures);
    }

    /// @dev The legacy ABI ERC-1271 blob is no longer accepted by the wallet.
    function test_safeOwner_checkSignatures_revertsWhen_legacyAbiEnvelope() public {
        bytes32 txHash = _txHash(safe1of1);
        SafeSig[] memory sigs = new SafeSig[](1);
        sigs[0] = SafeSig(
            address(quipA.wallet), true, _legacyErc1271Blob(txHash)
        );
        bytes memory signatures = _buildSafeSignatures(sigs);
        vm.expectRevert(bytes("GS024"));
        safe1of1.checkSignatures(address(0), txHash, signatures);
    }

    /* ─────────────────────────────────── helpers ─────────────────────────────────── */

    function _owners1(address a) internal pure returns (address[] memory owners) {
        owners = new address[](1);
        owners[0] = a;
    }

    function _owners2(address a, address b) internal pure returns (address[] memory owners) {
        owners = new address[](2);
        owners[0] = a;
        owners[1] = b;
    }

    function _deploySafe(address[] memory owners, uint256 threshold, uint256 salt) internal returns (ISafe150) {
        bytes memory initializer = abi.encodeCall(
            ISafe150.setup,
            (owners, threshold, address(0), "", SafeCode.FALLBACK_HANDLER_ADDRESS, address(0), 0, payable(address(0)))
        );
        return ISafe150(
            ISafeProxyFactory150(SafeCode.PROXY_FACTORY_ADDRESS).createProxyWithNonce(
                SafeCode.SAFE_ADDRESS, initializer, salt
            )
        );
    }

    /// @dev A second factory-deployed Quip wallet with its own keys and classical owner.
    function _deploySecondQuipWallet() internal returns (QuipOwner memory q) {
        (address ownerB, uint256 ownerBKey) = makeAddrAndKey("quipOwnerB");
        vm.deal(ownerB, 1 ether);
        bool ok;
        (, SHRINCS.PublicKey memory mainPkB, bool okMain) =
            SHRINCSTestSigner.keygen("safe-owner-quip-b-main", MAX_SIG);
        SHRINCS.SigningKey memory keyB;
        SHRINCS.PublicKey memory pkB;
        (keyB, pkB, ok) = SHRINCSTestSigner.keygen("safe-owner-quip-b-erc1271", MAX_SIG);
        assertTrue(okMain && ok, "quip B keygen");
        bytes32 mainCommitmentB = _commitment32(mainPkB);
        bytes32 erc1271CommitmentB = _commitment32(pkB);
        bytes memory payload = _buildInitPayload(
            mainCommitmentB, _toBytes32(mainPkB.pkSeed), mainPkB, HashSuite.HASH_SUITE_ID, pkB, HashSuite.HASH_SUITE_ID
        );
        vm.prank(ownerB);
        address walletB = factory.deployLatestWalletProxy(
            Codec.v1Commitment(mainCommitmentB, erc1271CommitmentB, ownerB), payable(ownerB), payload
        );
        q = QuipOwner(ShrincsWalletHarness(payable(walletB)), keyB, pkB, erc1271CommitmentB, ownerBKey);
    }

    /// @dev The ERC-1271 envelope `q.wallet` accepts for `hash`, signed live against its
    ///      nonce / keyVersion: the raw hash is signed directly (no personal-sign prefix).
    function _quipSig(QuipOwner memory q, bytes32 hash) internal returns (SafeSig memory) {
        SHRINCS.ActionContext memory ctx = Codec.buildActionContext(
            q.wallet.exposed_shrincsDomainSeparator(), q.wallet.actionNonce(), q.wallet.keyVersion(),
            Codec.ACTION_ERC1271, hash
        );
        bytes memory message = abi.encodePacked(
            SHRINCS.statelessRawMessageHash(
                q.erc1271Commitment, SHRINCS.statelessActionMessageHash(q.erc1271Commitment, ctx)
            )
        );
        bytes memory sig = _signStatelessRaw(q.erc1271Key, q.erc1271Pk, message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(q.ownerKey, q.wallet.quipSignedHashEcdsaTarget(hash));
        return SafeSig(address(q.wallet), true, _erc1271Envelope(q.erc1271Pk, sig, abi.encodePacked(r, s, v)));
    }

    function _eoaSig(uint256 key, bytes32 hash) internal pure returns (SafeSig memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash);
        return SafeSig(vm.addr(key), false, abi.encodePacked(r, s, v));
    }

    /// @dev Safe's signature blob: owners sorted ascending; a 65-byte static part each (EOA
    ///      ECDSA, or `r = owner, s = offset, v = 0` for a contract), then the contract
    ///      signatures' dynamic parts `len || data` at the recorded offsets.
    function _buildSafeSignatures(SafeSig[] memory sigs) internal pure returns (bytes memory out) {
        for (uint256 i = 1; i < sigs.length; ++i) {
            for (uint256 j = i; j > 0 && sigs[j - 1].owner > sigs[j].owner; --j) {
                (sigs[j - 1], sigs[j]) = (sigs[j], sigs[j - 1]);
            }
        }
        bytes memory dynamicPart;
        uint256 staticLen = 65 * sigs.length;
        for (uint256 i; i < sigs.length; ++i) {
            if (sigs[i].isContract) {
                out = abi.encodePacked(
                    out, bytes32(uint256(uint160(sigs[i].owner))), bytes32(staticLen + dynamicPart.length), uint8(0)
                );
                dynamicPart = abi.encodePacked(dynamicPart, sigs[i].data.length, sigs[i].data);
            } else {
                out = abi.encodePacked(out, sigs[i].data);
            }
        }
        out = abi.encodePacked(out, dynamicPart);
    }

    function _txHash(ISafe150 safe) internal view returns (bytes32) {
        return safe.getTransactionHash(
            RECIPIENT, SEND_VALUE, "", 0, 0, 0, 0, address(0), address(0), safe.nonce()
        );
    }

    function _exec(ISafe150 safe, bytes memory signatures) internal returns (bool) {
        return safe.execTransaction(
            RECIPIENT, SEND_VALUE, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures
        );
    }

    /// @dev Executes, asserts the transfer landed and the Safe nonce advanced, and logs the
    ///      execution gas plus the calldata size / intrinsic calldata gas of the call.
    function _execAndReport(ISafe150 safe, bytes memory signatures, string memory label) internal {
        uint256 nonceBefore = safe.nonce();
        uint256 recipientBefore = RECIPIENT.balance;
        bytes memory callData = abi.encodeCall(
            ISafe150.execTransaction,
            (RECIPIENT, SEND_VALUE, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures)
        );
        uint256 gasBefore = gasleft();
        bool success = _exec(safe, signatures);
        uint256 used = gasBefore - gasleft();
        assertTrue(success, "execTransaction succeeded");
        assertEq(RECIPIENT.balance - recipientBefore, SEND_VALUE, "value delivered");
        assertEq(safe.nonce(), nonceBefore + 1, "Safe nonce advanced");
        emit log_named_uint(label, used);
        emit log_named_uint("  calldata bytes", callData.length);
        emit log_named_uint("  calldata gas (EIP-2028)", _calldataGas(callData));
    }
}
