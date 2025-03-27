"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EVENTS = exports.ERRORS = exports.DEFAULT_CONFIRMATIONS = exports.DEFAULT_GAS_LIMIT = void 0;
exports.DEFAULT_GAS_LIMIT = 500000;
exports.DEFAULT_CONFIRMATIONS = 1;
exports.ERRORS = {
    INVALID_NETWORK: 'Invalid network specified',
    INSUFFICIENT_BALANCE: 'Insufficient balance',
    UNAUTHORIZED: 'Unauthorized operation'
};
exports.EVENTS = {
    WALLET_CREATED: 'WalletCreated',
    DEPOSIT_RECEIVED: 'DepositReceived',
    WITHDRAWAL_COMPLETED: 'WithdrawalCompleted'
};
