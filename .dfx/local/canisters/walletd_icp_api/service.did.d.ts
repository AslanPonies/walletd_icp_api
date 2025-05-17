import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export interface Account {
  'owner' : Principal,
  'subaccount' : [] | [Uint8Array | number[]],
}
export interface ApproveArgs {
  'fee' : [] | [bigint],
  'memo' : [] | [Uint8Array | number[]],
  'from_subaccount' : [] | [Uint8Array | number[]],
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
  'expected_allowance' : [] | [bigint],
  'expires_at' : [] | [bigint],
  'spender' : Account,
}
export interface CrossChainTx {
  'to_chain' : string,
  'from_chain' : string,
  'to_address' : string,
  'from_address' : string,
  'amount' : bigint,
}
export interface IcpTransaction {
  'to' : Principal,
  'signature' : Uint8Array | number[],
  'from' : Principal,
  'memo' : [] | [bigint],
  'amount' : bigint,
}
export type IcpWalletError = { 'Custom' : string } |
  { 'WalletNotFound' : null } |
  { 'InsufficientFunds' : null };
export interface TransferFromArgs {
  'to' : Account,
  'fee' : [] | [bigint],
  'spender_subaccount' : [] | [Uint8Array | number[]],
  'from' : Account,
  'memo' : [] | [Uint8Array | number[]],
  'created_at_time' : [] | [bigint],
  'amount' : bigint,
}
export interface _SERVICE {
  'approve' : ActorMethod<[string, string, bigint], bigint>,
  'balance' : ActorMethod<[string], bigint>,
  'generate_address' : ActorMethod<[], string>,
  'new_wallet' : ActorMethod<[], undefined>,
  'resolve_did' : ActorMethod<[string], [] | [Principal]>,
  'swap_icp_to_btc' : ActorMethod<[Principal, string, bigint], undefined>,
  'sync_balance' : ActorMethod<[], undefined>,
  'transaction_history' : ActorMethod<[string], Array<IcpTransaction>>,
  'transfer' : ActorMethod<[string, string, bigint], undefined>,
  'transfer_from' : ActorMethod<[string, string, string, bigint], bigint>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
