// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";

bytes4 constant SEL_RENOUNCE = bytes4(keccak256("renounceOwnership()"));
bytes4 constant SEL_TRANSFER = bytes4(keccak256("transferOwnership(address)"));
bytes4 constant SEL_REQUEST = bytes4(keccak256("requestOwnershipHandover()"));
bytes4 constant SEL_CANCEL = bytes4(keccak256("cancelOwnershipHandover()"));
bytes4 constant SEL_COMPLETE = bytes4(
    keccak256("completeOwnershipHandover(address)")
);
bytes4 constant SEL_WITHDRAW = bytes4(
    keccak256("withdrawDepositTo(address,uint256)")
);
bytes4 constant SEL_EXECUTE = bytes4(
    keccak256("execute(address,uint256,bytes)")
);
bytes4 constant SEL_EXECUTE_BATCH = bytes4(
    keccak256("executeBatch((address,uint256,bytes)[])")
);
bytes4 constant SEL_DELEGATE = bytes4(
    keccak256("delegateExecute(address,bytes)")
);
bytes4 constant SEL_STORE = bytes4(keccak256("storageStore(bytes32,bytes32)"));

contract ShrincsWalletInvariantHandler is Test {
    ShrincsWalletHarness public wallet;
    address public owner;

    struct ValidMark {
        SHRINCS.PublicKey pk;
        SHRINCS.Signature sig;
        uint32[] leaves;
    }

    ValidMark[] internal validPool;

    bool[] internal leafSeen;
    uint256 internal seenCount;

    uint256 public callsDisabled;
    uint256 public callsInvalidMark;
    uint256 public callsValidMark;
    uint256 public badReasonCount;
    uint256 public revertCount;

    function initialize(ShrincsWalletHarness wallet_, address owner_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
        leafSeen = new bool[](uint256(wallet.maxSignatures()) + 1);
    }

    function pushValidMark(
        SHRINCS.PublicKey calldata pk,
        SHRINCS.Signature calldata sig,
        uint32[] calldata leaves
    ) external {
        validPool.push();
        ValidMark storage slot = validPool[validPool.length - 1];
        slot.pk = pk;
        slot.sig = sig;
        slot.leaves = leaves;
    }

    function validPoolLength() external view returns (uint256) {
        return validPool.length;
    }

    function everSeenCount() external view returns (uint256) {
        return seenCount;
    }

    function isSeen(uint256 leaf) external view returns (bool) {
        if (leaf >= leafSeen.length) return false;
        return leafSeen[leaf];
    }

    function recordSeedMark(
        uint32 authLeaf,
        uint32[] calldata targets
    ) external {
        _recordExpectedLeaf(authLeaf);
        for (uint256 i = 0; i < targets.length; i++) {
            _recordExpectedLeaf(targets[i]);
        }
    }

    function _recordExpectedLeaf(uint256 leaf) internal {
        require(
            leaf > 0 && leaf < leafSeen.length,
            "expected leaf outside range"
        );
        if (leafSeen[leaf]) return;
        leafSeen[leaf] = true;
        seenCount++;
    }

    function _expectRevert(
        bytes memory data,
        bytes4 expected,
        bool ownerGated
    ) internal {
        if (ownerGated) vm.prank(owner);
        (bool ok, bytes memory ret) = address(wallet).call(data);
        if (ok) {
            callsDisabled++;
            return;
        }
        bytes4 revertSelector;
        if (ret.length >= 4) {
            assembly ("memory-safe") {
                revertSelector := mload(add(ret, 0x20))
            }
        }
        if (revertSelector == expected) {
            revertCount++;
        } else {
            badReasonCount++;
        }
    }

    function _garbagePk() internal pure returns (SHRINCS.PublicKey memory pk) {
        pk.statefulPublicKey = new bytes(0);
        pk.publicKeyCommitment = new bytes(0);
        pk.pkSeed = new bytes(0);
        pk.hypertreeRoot = new bytes(0);
    }

    function _garbageSig(
        uint8 authLen
    ) internal pure returns (SHRINCS.Signature memory sig) {
        authLen = uint8(bound(authLen, 0, 45));
        sig.authPath = new bytes32[](authLen);
        sig.chains = new bytes32[](0);
    }

    function fuzzDisabledRenounce() external {
        _expectRevert(
            abi.encodeWithSelector(SEL_RENOUNCE),
            Ownable.Unauthorized.selector,
            false
        );
        _expectRevert(
            abi.encodeWithSelector(SEL_RENOUNCE),
            IShrincsWallet.RenounceDisabled.selector,
            true
        );
    }

    function fuzzClassicalTransfer(address newOwner) external {
        _expectRevert(
            abi.encodeWithSelector(SEL_TRANSFER, newOwner),
            IShrincsWallet.ClassicalTransferOwnershipDisabled.selector,
            true
        );
    }

    function fuzzHandover(uint8 which, address pending) external {
        which = uint8(bound(which, 0, 2));
        if (which == 0) {
            _expectRevert(
                abi.encodeWithSelector(SEL_REQUEST),
                IShrincsWallet.OwnershipHandoverDisabled.selector,
                true
            );
        } else if (which == 1) {
            _expectRevert(
                abi.encodeWithSelector(SEL_CANCEL),
                IShrincsWallet.OwnershipHandoverDisabled.selector,
                true
            );
        } else {
            _expectRevert(
                abi.encodeWithSelector(SEL_COMPLETE, pending),
                IShrincsWallet.OwnershipHandoverDisabled.selector,
                true
            );
        }
    }

    function fuzzClassicalWithdraw(address to, uint256 amount) external {
        _expectRevert(
            abi.encodeWithSelector(SEL_WITHDRAW, to, amount),
            IShrincsWallet.ClassicalWithdrawDisabled.selector,
            true
        );
    }

    function fuzzDisabledExecute(
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        _expectRevert(
            abi.encodeWithSelector(SEL_EXECUTE, target, value, data),
            IShrincsWallet.StandardExecuteDisabled.selector,
            false
        );
        ERC4337.Call[] memory calls = new ERC4337.Call[](1);
        calls[0] = ERC4337.Call({target: target, value: value, data: data});
        _expectRevert(
            abi.encodeWithSelector(SEL_EXECUTE_BATCH, calls),
            IShrincsWallet.StandardExecuteDisabled.selector,
            false
        );
    }

    function fuzzDisabledDelegate(
        address target,
        bytes calldata data,
        bytes32 slot,
        bytes32 val
    ) external {
        _expectRevert(
            abi.encodeWithSelector(SEL_DELEGATE, target, data),
            IShrincsWallet.DelegateExecuteDisabled.selector,
            false
        );
        _expectRevert(
            abi.encodeWithSelector(SEL_STORE, slot, val),
            IShrincsWallet.StorageStoreDisabled.selector,
            false
        );
    }

    function fuzzInvalidMarkLeavesUsed(
        uint32 a,
        uint32 b,
        uint8 n,
        uint8 authLen
    ) external {
        uint32 maxSig = wallet.maxSignatures();
        n = uint8(bound(n, 0, 3));
        uint32[] memory leaves = new uint32[](n);
        if (n > 0) leaves[0] = uint32(bound(a, 0, uint256(maxSig) + 1));
        if (n > 1) leaves[1] = uint32(bound(b, 0, uint256(maxSig) + 1));
        if (n > 2)
            leaves[2] = uint32(
                bound(uint256(a) ^ uint256(b), 0, uint256(maxSig) + 1)
            );
        vm.prank(owner);
        try wallet.markLeavesUsed(_garbagePk(), _garbageSig(authLen), leaves) {
            callsInvalidMark++;
        } catch {
            revertCount++;
        }
    }

    function fuzzValidMarkReplay(uint256 idx) external {
        if (validPool.length == 0) {
            revertCount++;
            return;
        }
        idx = bound(idx, 0, validPool.length - 1);
        ValidMark storage entry = validPool[idx];
        vm.prank(owner);
        try wallet.markLeavesUsed(entry.pk, entry.sig, entry.leaves) {
            callsValidMark++;
            _recordExpectedLeaf(entry.sig.authPath.length);
            for (uint256 i = 0; i < entry.leaves.length; i++) {
                _recordExpectedLeaf(entry.leaves[i]);
            }
        } catch {
            revertCount++;
        }
    }
}
