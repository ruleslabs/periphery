%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_not_zero
from starkware.starknet.common.syscalls import delegate_call, delegate_l1_handler

#
# Storage
#

@storage_var
func implementation_storage() -> (address : felt):
end

#
# Internals
#

func _get_implementation{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
  } () -> (implementation: felt):
  let (res) = implementation_storage.read()
  return (implementation=res)
end

func _set_implementation{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr
  } (implementation: felt):
  assert_not_zero(implementation)
  implementation_storage.write(implementation)
  return ()
end
