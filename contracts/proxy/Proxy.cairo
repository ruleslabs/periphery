%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import delegate_call, delegate_l1_handler

from contracts.proxy.Upgradable import _get_implementation, _set_implementation

#
# Initializer
#

@constructor
func constructor{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  } (implementation: felt, selector: felt, calldata_len: felt, calldata: felt*):
  _set_implementation(implementation)
  delegate_call(
    contract_address=implementation,
    function_selector=selector,
    calldata_size=calldata_len,
    calldata=calldata
  )
  return ()
end

#
# Business logic
#

@external
@raw_input
@raw_output
func __default__{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  } (selector : felt, calldata_size : felt, calldata : felt*) -> (retdata_size : felt, retdata : felt*):
  let (implementation) = _get_implementation()

  let (retdata_size : felt, retdata : felt*) = delegate_call(
    contract_address=implementation,
    function_selector=selector,
    calldata_size=calldata_size,
    calldata=calldata
  )
  return (retdata_size, retdata)
end

@l1_handler
@raw_input
func __l1_default__{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
  } (selector : felt, calldata_size : felt, calldata : felt*):
  let (implementation) = _get_implementation()

  delegate_l1_handler(
    contract_address=implementation,
    function_selector=selector,
    calldata_size=calldata_size,
    calldata=calldata
  )
  return ()
end

#
# Getters
#

@view
func get_implementation{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  } () -> (implementation: felt):
  let (implementation) = _get_implementation()
  return (implementation)
end
