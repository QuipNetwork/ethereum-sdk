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

// TODO: Verify WOTSPLUS_GAS_ESTIMATE is still accurate against current contract — may be consumed by frontend
export const WOTSPLUS_GAS_ESTIMATE = 850_000;
// TODO: Verify DEFAULT_CONFIRMATIONS is still used — may be consumed by frontend
export const DEFAULT_CONFIRMATIONS = 1;

/// Conservative default gas budgets for the ERC-4337 wallet validation +
/// execute path. Real values should come from state-override estimation in
/// `QuipWalletClient.prepareExecuteUserOp`; these are the fallback when the
/// caller skips estimation.
export const DEFAULT_VERIFICATION_GAS_LIMIT: bigint = 1_500_000n;
export const DEFAULT_CALL_GAS_LIMIT: bigint = 500_000n;
export const DEFAULT_PRE_VERIFICATION_GAS: bigint = 80_000n;

/// Default gas budgets for the paymaster validation + postOp paths. These
/// are conservative — the paymaster operator can override either based on
/// operational data.
export const DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT: bigint = 1_500_000n;
export const DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT: bigint = 100_000n;
