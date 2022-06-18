%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_not_zero
from starkware.starknet.common.syscalls import library_call, library_call_l1_handler

#
# Storage
#

@storage_var
func ProxyImplementation() -> (address: felt):
end

namespace Proxy:

  #
  # Initializer
  #

  func initializer{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }(implementation: felt, selector: felt, calldata_size: felt, calldata: felt*):
    ProxyImplementation.write(implementation)
    library_call(
      class_hash=implementation,
      function_selector=selector,
      calldata_size=calldata_size,
      calldata=calldata
    )
    return ()
  end

  #
  # Getters
  #

  func get_implementation{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }() -> (implementation: felt):
    let (res) = ProxyImplementation.read()
    return (implementation=res)
  end

  #
  # Setters
  #

  func set_implementation{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }(implementation: felt):
    assert_not_zero(implementation)
    ProxyImplementation.write(implementation)
    return ()
  end

  #
  # Business logic
  #

  func default{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }(selector: felt, calldata_size: felt, calldata: felt*) -> (retdata_size: felt, retdata: felt*):
    let (implementation) = ProxyImplementation.read()

    let res = library_call(
      class_hash=implementation,
      function_selector=selector,
      calldata_size=calldata_size,
      calldata=calldata
    )
    return (retdata_size=res.retdata_size, retdata=res.retdata)
  end

  func l1_default{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }(selector: felt, calldata_size: felt, calldata: felt*):
    let (implementation) = ProxyImplementation.read()

    library_call_l1_handler(
      class_hash=implementation,
      function_selector=selector,
      calldata_size=calldata_size,
      calldata=calldata
    )
    return ()
  end
end
