# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (account/Account.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin

from periphery.account.library import Account, AccountCallArray

from periphery.introspection.ERC165 import ERC165

#
# Initializer
#

@external
func initialize{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }(signer_public_key: felt, guardian_public_key: felt):
  Account.initializer(signer_public_key, guardian_public_key)
  return ()
end

#
# Getters
#

@view
func get_version() -> (version: felt):
  let (version) = Account.get_version()
  return (version)
end

@view
func get_nonce{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }() -> (nonce: felt):
  let (nonce) = Account.get_nonce()
  return (nonce)
end

@view
func get_signer_public_key{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }() -> (public_key: felt):
  let (public_key) = Account.get_signer_public_key()
  return (public_key)
end

@view
func get_guardian_public_key{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }() -> (public_key: felt):
  let (public_key) = Account.get_guardian_public_key()
  return (public_key)
end

@view
func get_signer_escape{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }() -> (active_at: felt):
  let (active_at) = Account.get_signer_escape()
  return (active_at)
end

@view
func supportsInterface{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  } (interfaceId: felt) -> (success: felt):
  let (success) = ERC165.supports_interface(interfaceId)
  return (success)
end

#
# Setters
#

@external
func set_signer_public_key{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }(new_public_key: felt):
  Account.set_signer_public_key(new_public_key)
  return ()
end

@external
func set_guardian_public_key{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }(new_public_key: felt):
  Account.set_guardian_public_key(new_public_key)
  return ()
end

@external
func upgrade{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }(implementation: felt):
  Account.upgrade(implementation)
  return ()
end

# Escape

@external
func trigger_signer_escape{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }():
  Account.trigger_signer_escape()
  return ()
end

@external
func cancel_escape{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }():
  Account.cancel_escape()
  return ()
end

@external
func escape_signer{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  }(new_signer_public_key: felt):
  Account.escape_signer(new_signer_public_key)
  return ()
end

#
# Business logic
#

@view
func is_valid_signature{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
  }(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt):
  let (is_valid) = Account.is_valid_signature(hash, signature_len, signature)
  return (is_valid)
end

@external
func __execute__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*
  }(
    call_array_len: felt,
    call_array: AccountCallArray*,
    calldata_len: felt,
    calldata: felt*,
    nonce: felt
  ) -> (response_len: felt, response: felt*):
  let (response_len, response) = Account.execute(
    call_array_len,
    call_array,
    calldata_len,
    calldata,
    nonce
  )
  return (response_len=response_len, response=response)
end
