export const idlFactory = ({ IDL }) => {
  const IcpTransaction = IDL.Record({
    'to' : IDL.Principal,
    'signature' : IDL.Vec(IDL.Nat8),
    'from' : IDL.Principal,
    'memo' : IDL.Opt(IDL.Nat64),
    'amount' : IDL.Nat64,
  });
  return IDL.Service({
    'approve' : IDL.Func([IDL.Text, IDL.Text, IDL.Nat64], [IDL.Nat64], []),
    'balance' : IDL.Func([IDL.Text], [IDL.Nat64], []),
    'generate_address' : IDL.Func([], [IDL.Text], ['query']),
    'new_wallet' : IDL.Func([], [], ['oneway']),
    'resolve_did' : IDL.Func([IDL.Text], [IDL.Opt(IDL.Principal)], ['query']),
    'swap_icp_to_btc' : IDL.Func(
        [IDL.Principal, IDL.Text, IDL.Nat64],
        [],
        ['oneway'],
      ),
    'sync_balance' : IDL.Func([], [], ['oneway']),
    'transaction_history' : IDL.Func(
        [IDL.Text],
        [IDL.Vec(IcpTransaction)],
        ['query'],
      ),
    'transfer' : IDL.Func([IDL.Text, IDL.Text, IDL.Nat64], [], ['oneway']),
    'transfer_from' : IDL.Func(
        [IDL.Text, IDL.Text, IDL.Text, IDL.Nat64],
        [IDL.Nat64],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return []; };
