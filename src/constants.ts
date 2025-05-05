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
export const WOTSPLUS_GAS_ESTIMATE = 850_000;
export const DEFAULT_CONFIRMATIONS = 1;

export const ERRORS = {
  INVALID_NETWORK: "Invalid network specified",
  INSUFFICIENT_BALANCE: "Insufficient balance",
  UNAUTHORIZED: "Unauthorized operation",
} as const;

export const EVENTS = {
  WALLET_CREATED: "WalletCreated",
  DEPOSIT_RECEIVED: "DepositReceived",
  WITHDRAWAL_COMPLETED: "WithdrawalCompleted",
} as const;
