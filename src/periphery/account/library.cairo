%lang starknet

from starkware.cairo.common.bool import TRUE
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.math import assert_not_zero, assert_nn, assert_le
from starkware.starknet.common.syscalls import (
  call_contract, get_caller_address, get_tx_info, get_contract_address, get_block_timestamp, library_call
)

from periphery.introspection.ERC165 import ERC165

from periphery.utils.constants import IACCOUNT_ID
from periphery.proxy.library import Proxy

#
# Constants
#

const VERSION = '0.1.0'

const TRIGGER_ESCAPE_SIGNER_SELECTOR = 823970870440803648323000253851988489761099050950583820081611025987402410277
const ESCAPE_SIGNER_SELECTOR = 578307412324655990419134484880427622068887477430675222732446709420063579565
const SUPPORTS_INTERFACE_SELECTOR = 1184015894760294494673613438913361435336722154500302038630992932234692784845

const ESCAPE_SECURITY_PERIOD = 7 * 24 * 60 * 60 # set to e.g. 7 days in prod

#
# Structs
#

struct Call:
  member to: felt
  member selector: felt
  member calldata_len: felt
  member calldata: felt*
end

# Tmp struct introduced while we wait for Cairo
# to support passing `[AccountCall]` to __execute__
struct AccountCallArray:
  member to: felt
  member selector: felt
  member data_offset: felt
  member data_len: felt
end

struct Escape:
  member active_at: felt
end

#
# Storage
#

@storage_var
func Account_signer_public_key() -> (res: felt):
end

@storage_var
func Account_guardian_public_key() -> (res: felt):
end

@storage_var
func Account_current_nonce() -> (res: felt):
end

@storage_var
func Account_signer_escape() -> (res: Escape):
end

#
# Events
#

@event
func AccountUpgraded(new_implementation: felt):
end

@event
func AccountInitialized(signer_public_key: felt, guardian_public_key: felt):
end

@event
func TransactionExecuted(hash: felt, response_len: felt, response: felt*):
end

@event
func SignerPublicKeyChanged(new_public_key: felt):
end

@event
func GuardianPublicKeyChanged(new_public_key: felt):
end

@event
func SignerEscapeTriggered(active_at: felt):
end

@event
func SignerEscaped(active_at: felt):
end

@event
func EscapeCanceled():
end

namespace Account:

  #
  # Initializer
  #

  func initializer{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }(signer_public_key: felt, guardian_public_key: felt):
    # check that we are not already initialized
    let (current_signer_public_key) = Account_signer_public_key.read()
    with_attr error_message("Account: already initialized"):
        assert current_signer_public_key = 0
    end

    # check that the target signer is not zero
    with_attr error_message("Account: signer public key cannot be null"):
      assert_not_zero(signer_public_key)
    end

    Account_signer_public_key.write(signer_public_key)
    Account_guardian_public_key.write(guardian_public_key)

    ERC165.register_interface(IACCOUNT_ID)

    # emit event
    AccountInitialized.emit(signer_public_key, guardian_public_key)
    return()
  end

  #
  # Guards
  #

  func assert_only_self{ syscall_ptr : felt* }():
    let (self) = get_contract_address()
    let (caller) = get_caller_address()
    with_attr error_message("Account: caller is not this account"):
      assert self = caller
    end
    return ()
  end

  func assert_non_reentrant{ syscall_ptr: felt* } () -> ():
    let (caller) = get_caller_address()
    with_attr error_message("Account: no reentrant call"):
      assert caller = 0
    end
    return()
  end

  func assert_initialized{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }():
    let (signer) = Account_signer_public_key.read()
    with_attr error_message("Account: not initialized"):
      assert_not_zero(signer)
    end
    return()
  end

  func assert_no_self_call(
      self: felt,
      calls_len: felt,
      calls: Call*
    ):
    if calls_len == 0:
      return ()
    end

    assert_not_zero(calls[0].to - self)
    assert_no_self_call(self, calls_len - 1, calls + Call.SIZE)
    return()
  end

  func assert_guardian_set{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }():
    let (guardian) = Account_guardian_public_key.read()
    with_attr error_message("Account: guardian must be set"):
      assert_not_zero(guardian)
    end
    return()
  end

  #
  # Getters
  #

  func get_version() -> (version: felt):
    return (version=VERSION)
  end

  func get_signer_public_key{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }() -> (res: felt):
    let (res) = Account_signer_public_key.read()
    return (res=res)
  end

  func get_guardian_public_key{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }() -> (res: felt):
    let (res) = Account_guardian_public_key.read()
    return (res=res)
  end

  func get_nonce{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }() -> (nonce: felt):
    let (res) = Account_current_nonce.read()
    return (nonce=res)
  end

  func get_signer_escape{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }() -> (active_at: felt):
    let (res) = Account_signer_escape.read()
    return (active_at=res.active_at)
  end

  #
  # Setters
  #

  func set_signer_public_key{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
  }(new_public_key: felt):
    # only called via execute
    assert_only_self()

    # check that the target signer is not zero
    with_attr error_message("Account: signer public key cannot be null"):
      assert_not_zero(new_public_key)
    end

    Account_signer_public_key.write(new_public_key)
    SignerPublicKeyChanged.emit(new_public_key)
    return ()
  end

  func set_guardian_public_key{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
  }(new_public_key: felt):
    # only called via execute
    assert_only_self()

    Account_guardian_public_key.write(new_public_key)
    GuardianPublicKeyChanged.emit(new_public_key)
    return ()
  end

  func upgrade{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr
    }(implementation: felt):
    # only called via execute
    assert_only_self()

    # make sure the target is an account
    with_attr error_message("Account: invalid implementation"):
      let (calldata: felt*) = alloc()
      assert calldata[0] = IACCOUNT_ID

      let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=implementation,
        function_selector=SUPPORTS_INTERFACE_SELECTOR,
        calldata_size=1,
        calldata=calldata
      )

      assert retdata_size = 1
      assert [retdata] = TRUE
    end

    # change implementation
    Proxy.set_implementation(implementation)
    AccountUpgraded.emit(new_implementation=implementation)
    return ()
  end

  #
  # Business logic
  #

  func is_valid_signature{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr,
      ecdsa_ptr: SignatureBuiltin*
    }(hash: felt, signature_len: felt, signature: felt*) -> (is_valid: felt):
    let (is_valid) = validate_signer_signature(hash, signature_len, signature)
    return (is_valid)
  end

  func execute{
      syscall_ptr : felt*,
      pedersen_ptr : HashBuiltin*,
      range_check_ptr,
      ecdsa_ptr: SignatureBuiltin*
    }(
      call_array_len: felt,
      call_array: AccountCallArray*,
      calldata_len: felt,
      calldata: felt*,
      nonce: felt
    ) -> (response_len: felt, response: felt*):
    alloc_locals

    # make sure the account is initialized
    assert_initialized()
    # no reentrant call to prevent signature reutilization
    assert_non_reentrant()

    # TMP: Convert `AccountCallArray` to 'Call'.
    let (calls : Call*) = alloc()
    _from_call_array_to_call(call_array_len, call_array, calldata, calls)
    let calls_len = call_array_len

    # validate nonce
    validate_and_bump_nonce(nonce)

    # get the tx info
    let (tx_info) = get_tx_info()

    if calls_len == 1:
      if calls[0].to == tx_info.account_contract_address:
        tempvar guardian_condition = (calls[0].selector - ESCAPE_SIGNER_SELECTOR) * (calls[0].selector - TRIGGER_ESCAPE_SIGNER_SELECTOR)

        if guardian_condition == 0:
          # validate guardian signature
          validate_guardian_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature)
          jmp do_execute
        end
      end
    else:
        # make sure no call is to the account
        assert_no_self_call(tx_info.account_contract_address, calls_len, calls)
    end

    # validate transaction
    validate_signer_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature)

    # execute call
    do_execute:
    local ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr
    local syscall_ptr: felt* = syscall_ptr
    local range_check_ptr = range_check_ptr
    local pedersen_ptr: HashBuiltin* = pedersen_ptr

    let (response : felt*) = alloc()
    let (response_len) = _execute_list(calls_len, calls, response)

    # emit event
    TransactionExecuted.emit(hash=tx_info.transaction_hash, response_len=response_len, response=response)
    return (response_len=response_len, response=response)
  end

  # Escape

  func trigger_signer_escape{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }():
    # only called via execute
    assert_only_self()
    # no escape when there is no guardian set
    assert_guardian_set()

    # store new escape
    let (block_timestamp) = get_block_timestamp()
    let new_escape: Escape = Escape(block_timestamp + ESCAPE_SECURITY_PERIOD)
    Account_signer_escape.write(new_escape)
    SignerEscapeTriggered.emit(active_at=block_timestamp + ESCAPE_SECURITY_PERIOD)

    return()
  end

  func cancel_escape{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }():
    # only called via execute
    assert_only_self()

    # validate there is an active escape
    let (current_signer_escape) = Account_signer_escape.read()
    with_attr error_message("Account: no escape to cancel"):
      assert_not_zero(current_signer_escape.active_at)
    end

    # clear escape
    let new_escape: Escape = Escape(0)
    Account_signer_escape.write(new_escape)
    EscapeCanceled.emit()

    return()
  end

  func escape_signer{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }(new_signer_public_key: felt):
    alloc_locals

    # only called via execute
    assert_only_self()
    # no escape when the guardian is not set
    assert_guardian_set()

    let (current_signer_escape) = Account_signer_escape.read()
    let (block_timestamp) = get_block_timestamp()
    with_attr error_message("Account: invalid escape"):
      # validate there is an active escape
      assert_not_zero(current_signer_escape.active_at)
      assert_le(current_signer_escape.active_at, block_timestamp)
    end

    # clear escape
    let new_escape: Escape = Escape(0)
    Account_signer_escape.write(new_escape)

    # change signer
    with_attr error_message("Account: new signer public key cannot be null"):
      # check that the target signer is not zero
      assert_not_zero(new_signer_public_key)
    end
    Account_signer_public_key.write(new_signer_public_key)
    SignerEscaped.emit(new_signer_public_key)

    return()
  end

  #
  # Internals
  #

  func validate_and_bump_nonce{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      range_check_ptr
    }(message_nonce: felt) -> ():
    let (current_nonce) = Account_current_nonce.read()
    with_attr error_message("Account: invalid nonce"):
      assert current_nonce = message_nonce
    end

    Account_current_nonce.write(current_nonce + 1)
    return()
  end

  # Signatures

  func validate_signer_signature{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      ecdsa_ptr: SignatureBuiltin*,
      range_check_ptr
    }(message: felt, signatures_len: felt, signatures: felt*) -> (is_valid: felt):
    with_attr error_message("Account: invalid signer signature"):
      assert_nn(signatures_len - 2)
      let (public_key) = Account_signer_public_key.read()

      verify_ecdsa_signature(
        message=message,
        public_key=public_key,
        signature_r=signatures[0],
        signature_s=signatures[1]
      )
    end

    return(is_valid=TRUE)
  end

  func validate_guardian_signature{
      syscall_ptr: felt*,
      pedersen_ptr: HashBuiltin*,
      ecdsa_ptr: SignatureBuiltin*,
      range_check_ptr
    }(message: felt, signatures_len: felt, signatures: felt*) -> (is_valid: felt):
    let (public_key) = Account_guardian_public_key.read()

    if public_key == 0:
      return(is_valid=TRUE)
    else:
      with_attr error_message("Account: invalid guardian signature"):
        assert_nn(signatures_len - 2)

        verify_ecdsa_signature(
          message=message,
          public_key=public_key,
          signature_r=signatures[0],
          signature_s=signatures[1]
        )
      end
    end

    return(is_valid=TRUE)
  end

  # Execute

  func _execute_list{syscall_ptr: felt*}(
      calls_len: felt,
      calls: Call*,
      response: felt*
    ) -> (response_len: felt):
    alloc_locals

    # if no more calls
    if calls_len == 0:
       return (0)
    end

    # do the current call
    let this_call: Call = [calls]
    let res = call_contract(
      contract_address=this_call.to,
      function_selector=this_call.selector,
      calldata_size=this_call.calldata_len,
      calldata=this_call.calldata
    )
    # copy the result in response
    memcpy(response, res.retdata, res.retdata_size)
    # do the next calls recursively
    let (response_len) = _execute_list(calls_len - 1, calls + Call.SIZE, response + res.retdata_size)
    return (response_len + res.retdata_size)
  end

  func _from_call_array_to_call{syscall_ptr: felt*}(
      call_array_len: felt,
      call_array: AccountCallArray*,
      calldata: felt*,
      calls: Call*
    ):
    # if no more calls
    if call_array_len == 0:
       return ()
    end

    # parse the current call
    assert [calls] = Call(
        to=[call_array].to,
        selector=[call_array].selector,
        calldata_len=[call_array].data_len,
        calldata=calldata + [call_array].data_offset
      )
    # parse the remaining calls recursively
    _from_call_array_to_call(call_array_len - 1, call_array + AccountCallArray.SIZE, calldata, calls + Call.SIZE)
    return ()
  end
end
