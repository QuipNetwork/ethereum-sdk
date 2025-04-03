export const WOTSPLUS_GAS_ESTIMATE = 850_000;
export const DEFAULT_CONFIRMATIONS = 1;

export const ERRORS = {
  INVALID_NETWORK: 'Invalid network specified',
  INSUFFICIENT_BALANCE: 'Insufficient balance',
  UNAUTHORIZED: 'Unauthorized operation'
} as const;

export const EVENTS = {
  WALLET_CREATED: 'WalletCreated',
  DEPOSIT_RECEIVED: 'DepositReceived',
  WITHDRAWAL_COMPLETED: 'WithdrawalCompleted'
} as const;