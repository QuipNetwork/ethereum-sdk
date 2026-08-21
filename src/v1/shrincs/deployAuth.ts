// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Address, type Hex } from "viem";

import { type ShrincsKeyPair } from "./shrincsSigner.js";
import {
  ACTION_DEPLOY,
  DEPLOY_DOMAIN_TAG,
  buildActionContext,
  deployPayloadHash,
  domainSeparator,
} from "./shrincsCodec.js";
import {
  type ActionContext,
  type StatefulSignature,
  type StatelessSignature,
} from "./types.js";

/// Which deploy-authorization mode a factory requires (`e3r`). The factory
/// declares this at setup; `initialize` enforces it.
///   - `stateful`: a main-key stateful signature at the reserved deploy leaf
///     `quipDeployChainIndex`. One-time, distinct leaf per chain.
///   - `stateless`: a main-key stateless signature bound to the chainId. No leaf
///     consumed; the chainId binding is what prevents cross-chain reuse.
export type DeployAuthMode = "stateful" | "stateless";

export interface DeployAuthorizationParams {
  /// The wallet's main key, recovered from the signer for this `vaultId`.
  mainKey: ShrincsKeyPair;
  /// The chain the factory reports it is on (the authoritative source).
  chainId: number;
  /// The factory address — the deploy authority the signature is bound to.
  factoryAddress: Address;
  vaultId: Hex;
  /// The intended wallet owner (ECDSA admin).
  owner: Address;
  /// The dedicated ERC-1271 verifier commitment installed at deploy.
  erc1271Commitment: Hex;
  /// The factory's committed per-chain index. In `stateful` mode this is the
  /// reserved deploy leaf the signature is produced at.
  quipDeployChainIndex: number;
  mode: DeployAuthMode;
}

export interface DeployAuthorization {
  context: ActionContext;
  signature: StatefulSignature | StatelessSignature;
}

/// Build the deploy `ActionContext` for a deploy authorization. Bound to the
/// factory (chainId + factory address, via `DEPLOY_DOMAIN_TAG`) because the
/// wallet address does not yet exist, and to the deploy tuple via
/// `deployPayloadHash`. `nonce`/`keyVersion` are `0n`: the wallet is fresh, and
/// freshness comes from the one-time deploy leaf (stateful) or the chainId
/// binding (stateless), mirroring the paymaster exception.
export function buildDeployContext(
  params: Omit<DeployAuthorizationParams, "mainKey" | "mode">
): ActionContext {
  return buildActionContext({
    domainSeparator: domainSeparator(
      params.chainId,
      params.factoryAddress,
      DEPLOY_DOMAIN_TAG
    ),
    nonce: 0n,
    keyVersion: 0n,
    actionType: ACTION_DEPLOY,
    payloadHash: deployPayloadHash(
      params.vaultId,
      params.owner,
      params.erc1271Commitment,
      params.quipDeployChainIndex
    ),
  });
}

/// Produce a deploy authorization: the deploy context plus the main-key
/// signature the factory requires (`e3r`). Only the main-key holder can produce
/// it, so only they can initialize the wallet at its commitment-bound address.
export function buildDeployAuthorization(
  params: DeployAuthorizationParams
): DeployAuthorization {
  const context = buildDeployContext(params);
  const signature =
    params.mode === "stateful"
      ? params.mainKey.signStatefulActionAt(context, params.quipDeployChainIndex)
      : params.mainKey.signStatelessAction(context);
  return { context, signature };
}
