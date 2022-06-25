# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (account/IAccount.cairo)

%lang starknet

from periphery.account.library import AccountCallArray

@contract_interface
namespace IAccount:

  #
  # Business logic
  #

  func is_valid_signature(
    hash: felt,
    signature_len: felt,
    signature: felt*
  ):
  end

  func upgrade(
    implementation: felt
  ) -> (response_len: felt, response: felt*):
  end

  func __execute__(
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*,
    nonce: felt
  ) -> (response_len: felt, response: felt*):
  end
end
