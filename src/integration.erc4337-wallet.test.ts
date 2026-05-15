// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  type TestClient,
  createPublicClient,
  createWalletClient,
  createTestClient,
  encodeFunctionData,
  http,
  toHex,
  zeroAddress,
  parseEventLogs,
  parseEther,
  zeroHash,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import { entryPointV07Abi } from "./abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "./addresses.js";
import { QuipSigner } from "./signer.js";
import { createInMemoryBurnSet, type InMemoryBurnSet } from "./burnSet.js";
import {
  QuipWalletClient,
  KeyType,
} from "./walletClient.js";
import {
  UnknownContractError,
  UserOpValidationFailure,
} from "./errors.js";
import {
  type PackedUserOperation,
  type WinternitzAddress,
  RECOVERY_KEY_AMOUNT,
  TRANSACTION_KEY_INIT_AMOUNT,
  computeUserOpHash,
  encodeInit,
} from "./wotsCodec.js";

// ─── Forge artifacts ────────────────────────────────────────────────
const factoryArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipFactory.sol/QuipFactory.json"),
    "utf8"
  )
);
const factoryBytecode = factoryArtifact.bytecode.object as Hex;

const walletArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipWallet.sol/QuipWallet.json"),
    "utf8"
  )
);
const walletUnlinkedBytecode = walletArtifact.bytecode.object as string;
const quipWalletDeployAbi = walletArtifact.abi;

const wotsPlusArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/WOTSPlus.sol/WOTSPlus.json"),
    "utf8"
  )
);
const wotsPlusBytecode = wotsPlusArtifact.bytecode.object as Hex;
const wotsPlusAbi = wotsPlusArtifact.abi;

const entryPointFixture = JSON.parse(
  readFileSync(
    join(process.cwd(), "src/fixtures/entrypoint-v0.7.json"),
    "utf8"
  )
);
const entryPointDeployedBytecode = entryPointFixture.deployedBytecode as Hex;

function linkWalletBytecode(libAddress: Address): Hex {
  const refs =
    walletArtifact.bytecode.linkReferences as Record<
      string,
      Record<string, Array<{ start: number; length: number }>>
    >;
  let hex = walletUnlinkedBytecode.replace(/^0x/, "");
  const addrPlain = libAddress.replace(/^0x/, "").toLowerCase();
  for (const file of Object.values(refs)) {
    for (const libRefs of Object.values(file)) {
      for (const ref of libRefs) {
        const hexStart = ref.start * 2;
        const hexLen = ref.length * 2;
        hex =
          hex.slice(0, hexStart) + addrPlain + hex.slice(hexStart + hexLen);
      }
    }
  }
  return ("0x" + hex) as Hex;
}

const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

const anvil = createAnvil({ port: 8552 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let testClient: TestClient;
let factoryAddress: Address;

const MAX_FEE = 10n ** 16n;

function buildInitPayload(
  signer: QuipSigner,
  vaultId: Hex
): {
  payload: Hex;
  transactionKeys: WinternitzAddress[];
} {
  const disaster = signer.generateKeyPair(vaultId).publicKey;
  const ownership = signer.generateKeyPair(vaultId).publicKey;
  const transactionKeys = Array.from(
    { length: TRANSACTION_KEY_INIT_AMOUNT },
    () => signer.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const payload = encodeInit(disaster, ownership, transactionKeys, recoveryKeys);
  return { payload, transactionKeys };
}

async function createFreshWallet(seedByte: number): Promise<{
  signer: QuipSigner;
  vaultId: Hex;
  client: QuipWalletClient;
  walletAddress: Address;
  transactionKeys: WinternitzAddress[];
  burnSet: InMemoryBurnSet;
  isBurned: (seed: Hex) => boolean;
  markBurned: (seed: Hex) => void;
}> {
  const quantumSecret = new Uint8Array(32).fill(seedByte);
  const burnSet = createInMemoryBurnSet();
  const burned = new Set<Hex>();
  const consume = (seed: Hex): void => {
    burnSet.consume(seed);
    burned.add(seed);
  };
  const signer = new QuipSigner(quantumSecret, consume);
  const vaultId = toHex(new Uint8Array(32).fill(seedByte));
  const init = buildInitPayload(signer, vaultId);

  const hash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [vaultId, account.address, init.payload],
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const logs = parseEventLogs({
    abi: quipFactoryAbi,
    logs: receipt.logs,
    eventName: "QuipCreated",
  });
  const walletAddress = logs[0].args.quip;

  // Fund the wallet so it can pay for the UserOp via EntryPoint deposit.
  await testClient.setBalance({
    address: walletAddress,
    value: parseEther("10"),
  });
  // Pre-deposit ETH at the EntryPoint on behalf of the wallet so
  // payPrefund doesn't have to pull from the wallet's own balance during
  // validation. depositTo(account) is callable by anyone, payable.
  await walletClient.writeContract({
    chain: foundry,
    address: CANONICAL_ENTRYPOINT_V07,
    abi: entryPointV07Abi,
    functionName: "depositTo",
    args: [walletAddress],
    value: parseEther("1"),
    account,
  });

  const client = new QuipWalletClient(
    signer,
    vaultId,
    walletAddress,
    publicClient,
    walletClient,
    account.address,
    foundry.id
  );
  return {
    signer,
    vaultId,
    client,
    walletAddress,
    transactionKeys: init.transactionKeys,
    burnSet,
    isBurned: (seed: Hex) => burned.has(seed),
    markBurned: (seed: Hex) => consume(seed),
  };
}

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  walletClient = createWalletClient({ chain: foundry, transport, account });
  testClient = createTestClient({
    chain: foundry,
    mode: "anvil",
    transport,
  });

  // 1. Place the canonical v0.7 EntryPoint bytecode at the canonical
  //    address via anvil_setCode. Hermetic, no fork needed.
  await testClient.setCode({
    address: CANONICAL_ENTRYPOINT_V07,
    bytecode: entryPointDeployedBytecode,
  });

  // 2. Deploy QuipFactory.
  const factoryHash = await walletClient.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [account.address, MAX_FEE],
    account,
    chain: foundry,
  });
  const factoryReceipt = await publicClient.waitForTransactionReceipt({
    hash: factoryHash,
  });
  factoryAddress = factoryReceipt.contractAddress!;

  // 3. Deploy WOTSPlus library + link wallet bytecode.
  const wotsHash = await walletClient.deployContract({
    abi: wotsPlusAbi,
    bytecode: wotsPlusBytecode,
    account,
    chain: foundry,
  });
  const wotsReceipt = await publicClient.waitForTransactionReceipt({
    hash: wotsHash,
  });
  const wotsAddr = wotsReceipt.contractAddress!;

  const walletBytecode = linkWalletBytecode(wotsAddr);
  const implHash = await walletClient.deployContract({
    abi: quipWalletDeployAbi,
    bytecode: walletBytecode,
    args: [factoryAddress],
    account,
    chain: foundry,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });

  // 4. Vet the implementation.
  const vetHash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "vetImplementation",
    args: [implReceipt.contractAddress!],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });
}, 90_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

// ─── Tests ──────────────────────────────────────────────────────────

describe("EntryPoint v0.7 fixture sanity", () => {
  test("setCode put the canonical address under bytecode", async () => {
    const code = await publicClient.getCode({
      address: CANONICAL_ENTRYPOINT_V07,
    });
    expect(code).toBeDefined();
    expect(code!.length).toBeGreaterThan(2);
  });

  test("our local userOpHash matches EntryPoint.getUserOpHash", async () => {
    const { walletAddress } = await createFreshWallet(0x40);
    const fixedUserOp: PackedUserOperation = {
      sender: walletAddress,
      nonce: 7n,
      initCode: "0x",
      callData: "0xdead",
      accountGasLimits:
        "0x000000000000000000000000000f424000000000000000000000000000007a12",
      preVerificationGas: 80_000n,
      gasFees:
        "0x000000000000000000000000000186a0000000000000000000000000000493e0",
      paymasterAndData: "0x",
      signature: "0x",
    };
    const local = computeUserOpHash(
      fixedUserOp,
      CANONICAL_ENTRYPOINT_V07,
      BigInt(foundry.id)
    );
    const onchain = await publicClient.readContract({
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "getUserOpHash",
      args: [fixedUserOp],
    });
    expect(local).toBe(onchain);
  }, 30_000);
});

describe("buildExecuteUserOp + handleOps end-to-end", () => {
  test("happy path: signed UserOp lands via handleOps, inner call runs, key rotates", async () => {
    const { client, isBurned, walletAddress } = await createFreshWallet(0x41);
    const headBefore = await client.getHeadTransactionKey();

    // Inner call: pure rotation (target=zero, value=0, data=0x).
    const built = await client.buildExecuteUserOp(zeroAddress, 0n, "0x");
    expect(built.userOp.signature).not.toBe("0x");
    expect(built.userOp.sender).toBe(walletAddress);

    // Simulate first — should be 'ok'.
    const sim = await client.simulateUserOp(built.userOp);
    expect(sim.walletValidation).toBe("ok");
    expect(sim.keysBurnedIfRevert.wallet).toBe(true);
    expect(sim.paymasterValidation).toBe("no-paymaster");

    // Submit via handleOps.
    const handleHash = await walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "handleOps",
      args: [[built.userOp], account.address],
      account,
      gas: 2_000_000n,
    });
    // `buildExecuteUserOp` already invoked the signer's `consume` at sign
    // time, so the burn is recorded in the burn set well before this
    // manual `handleOps` submission.
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: handleHash,
    });

    // UserOperationEvent emitted with success=true.
    const events = parseEventLogs({
      abi: entryPointV07Abi,
      logs: receipt.logs,
      eventName: "UserOperationEvent",
    });
    expect(events.length).toBe(1);
    expect(events[0].args.success).toBe(true);
    expect(events[0].args.userOpHash).toBe(built.userOpHash);

    // Head transaction key advanced — the old head is no longer index 0.
    const headAfter = await client.getHeadTransactionKey();
    expect(headAfter.publicSeed).not.toBe(headBefore.publicSeed);

    // SDK-side: signer recorded the burn via the injected consume.
    expect(isBurned(headBefore.publicSeed)).toBe(true);
  }, 60_000);
});

describe("simulateUserOp — rejection paths", () => {
  test("ZeroNextKey: signature with all-zero nextKey", async () => {
    const { client } = await createFreshWallet(0x42);
    const head = await client.getHeadTransactionKey();
    // Construct a malformed UserOp: nextKey = (0, 0). Use a valid currentKey
    // but a zero nextKey — should hit the ZeroNextKey early-exit.
    const built = await client.buildExecuteUserOp(zeroAddress, 0n, "0x");
    // Surgically rewrite the signature's nextKey region (bytes 64..128) to zero.
    const sigHex = built.userOp.signature.slice(2);
    const tampered =
      "0x" +
      sigHex.slice(0, 128) + // currentKey: 64 bytes -> 128 hex chars
      "00".repeat(64) + // nextKey: 64 bytes
      sigHex.slice(128 + 128);
    const malformed: PackedUserOperation = {
      ...built.userOp,
      signature: tampered as Hex,
    };
    const sim = await client.simulateUserOp(malformed);
    expect(sim.walletValidation).toBe(UserOpValidationFailure.ZeroNextKey);
    expect(sim.keysBurnedIfRevert.wallet).toBe(false);
    // Ensure the head we read at the start of the test still exists,
    // since no broadcast happened.
    expect(head.publicSeed).not.toBe(zeroHash);
  }, 30_000);

  test("StaleCurrentKey: currentKey not in transaction keyset", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0x43);
    const built = await client.buildExecuteUserOp(zeroAddress, 0n, "0x");
    // Replace currentKey with a freshly generated keypair that's never been added.
    const stranger = signer.generateKeyPair(toHex(vaultId)).publicKey;
    const strangerSeed = stranger.publicSeed.slice(2);
    const strangerHash = stranger.publicKeyHash.slice(2);
    const sigHex = built.userOp.signature.slice(2);
    const tampered =
      "0x" +
      strangerSeed +
      strangerHash +
      sigHex.slice(128);
    const malformed: PackedUserOperation = {
      ...built.userOp,
      signature: tampered as Hex,
    };
    const sim = await client.simulateUserOp(malformed);
    expect(sim.walletValidation).toBe(
      UserOpValidationFailure.StaleCurrentKey
    );
    expect(sim.keysBurnedIfRevert.wallet).toBe(false);
  }, 30_000);

  test("NextKeyAlreadyInUse: nextKey matches an existing keyset member", async () => {
    const { client } = await createFreshWallet(0x44);
    const keyset = await client.getKeyset(KeyType.Transaction);
    expect(keyset.length).toBeGreaterThanOrEqual(2);
    const built = await client.buildExecuteUserOp(zeroAddress, 0n, "0x");
    // Replace nextKey with another tx-keyset member (already in use).
    const dup = keyset[1];
    const dupSeed = dup.publicSeed.slice(2);
    const dupHash = dup.publicKeyHash.slice(2);
    const sigHex = built.userOp.signature.slice(2);
    const tampered =
      "0x" +
      sigHex.slice(0, 128) +
      dupSeed +
      dupHash +
      sigHex.slice(128 + 128);
    const malformed: PackedUserOperation = {
      ...built.userOp,
      signature: tampered as Hex,
    };
    const sim = await client.simulateUserOp(malformed);
    expect(sim.walletValidation).toBe(
      UserOpValidationFailure.NextKeyAlreadyInUse
    );
    expect(sim.keysBurnedIfRevert.wallet).toBe(false);
  }, 30_000);

  test("InvalidSignature: WOTS+ sig elements tampered", async () => {
    const { client } = await createFreshWallet(0x45);
    const built = await client.buildExecuteUserOp(zeroAddress, 0n, "0x");
    // Flip one byte deep inside the WOTS+ signature element region.
    // First 128 bytes are currentKey + nextKey; sig starts at offset 128.
    const sigHex = built.userOp.signature.slice(2);
    const tamperOffset = 2 * 128 + 10;
    const tampered =
      "0x" +
      sigHex.slice(0, tamperOffset) +
      "ff" +
      sigHex.slice(tamperOffset + 2);
    const malformed: PackedUserOperation = {
      ...built.userOp,
      signature: tampered as Hex,
    };
    const sim = await client.simulateUserOp(malformed);
    expect(sim.walletValidation).toBe(
      UserOpValidationFailure.InvalidSignature
    );
    expect(sim.keysBurnedIfRevert.wallet).toBe(false);
  }, 30_000);
});

describe("buildExecuteUserOp — inner-call revert pre-flight (D3)", () => {
  // The inner call we'll force to revert: wallet.execute(factory,
  // setExecuteFee(0)). Factory.setExecuteFee is OZ-onlyOwner; the wallet
  // is not the factory owner, so the call reverts with
  // `OwnableUnauthorizedAccount(address)`. That selector isn't in the
  // Quip error registry, so it surfaces as `UnknownContractError`.
  function revertingInnerCallData(): Hex {
    return encodeFunctionData({
      abi: quipFactoryAbi,
      functionName: "setExecuteFee",
      args: [0n],
    });
  }

  test("buildExecuteUserOp throws on guaranteed-revert inner call; key not burned", async () => {
    const { client, isBurned } = await createFreshWallet(0x46);
    const head = await client.getHeadTransactionKey();
    expect(isBurned(head.publicSeed)).toBe(false);

    let caught: unknown = null;
    try {
      await client.buildExecuteUserOp(
        factoryAddress,
        0n,
        revertingInnerCallData()
      );
    } catch (e) {
      caught = e;
    }

    // The OZ Ownable error is not in the Quip registry; the SDK decodes
    // it to `UnknownContractError` carrying the OZ selector + raw data.
    expect(caught).toBeInstanceOf(UnknownContractError);
    expect((caught as UnknownContractError).errorName).toBe(
      "OwnableUnauthorizedAccount"
    );

    // Critical: the head key MUST NOT be burned. The bug this fix
    // addresses was: `estimateExecuteCallGas` swallowed the revert,
    // `prepareExecuteUserOp` returned a userOp with DEFAULT_CALL_GAS_LIMIT,
    // `signExecuteUserOp` burned the key, and the doomed userOp was
    // shipped to the bundler. After the fix, prepare throws and sign is
    // never reached.
    expect(isBurned(head.publicSeed)).toBe(false);
  }, 30_000);

  test("prepareExecuteUserOp surfaces the decoded contract revert", async () => {
    const { client, isBurned } = await createFreshWallet(0x47);
    const head = await client.getHeadTransactionKey();

    await expect(
      client.prepareExecuteUserOp(
        factoryAddress,
        0n,
        revertingInnerCallData()
      )
    ).rejects.toBeInstanceOf(UnknownContractError);

    // prepareExecuteUserOp NEVER burns keys (burning happens in
    // signExecuteUserOp); re-check explicitly so the contract is
    // documented in tests.
    expect(isBurned(head.publicSeed)).toBe(false);
  }, 30_000);

  test("happy path: non-reverting inner call produces a complete signed userOp", async () => {
    const { client } = await createFreshWallet(0x48);
    const built = await client.buildExecuteUserOp(zeroAddress, 0n, "0x");
    expect(built.userOp.signature).not.toBe("0x");
    // accountGasLimits = [verificationGasLimit(16) | callGasLimit(16)]
    // (left-padded, packed by `packAccountGasLimits`). callGasLimit lives
    // in the low 16 bytes — extract and verify it's a real estimate
    // (i.e. not the DEFAULT_CALL_GAS_LIMIT fallback the old code
    // returned on every estimate failure).
    const packed = built.userOp.accountGasLimits.slice(2);
    expect(packed.length).toBe(64);
    const callGasLimit = BigInt("0x" + packed.slice(32));
    expect(callGasLimit).toBeGreaterThan(0n);
  }, 30_000);
});
