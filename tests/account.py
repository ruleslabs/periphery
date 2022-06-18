import pytest
import asyncio
import logging

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo

from utils.Signer import Signer
from utils.misc import deploy, assert_revert, str_to_felt, assert_event_emmited
from utils.TransactionSender import TransactionSender

LOGGER = logging.getLogger(__name__)

signer = Signer(123456789987654321)
guardian = Signer(456789987654321123)

wrong_signer = Signer(666666666666666666)
wrong_guardian = Signer(6767676767)

DEFAULT_TIMESTAMP = 1640991600
ESCAPE_SECURITY_PERIOD = 24 * 7 * 60 * 60

VERSION = str_to_felt('0.1.0')

IACCOUNT_ID = 0xf10dbd44

@pytest.fixture(scope='module')
def event_loop():
  return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def get_starknet():
  starknet = await Starknet.empty()
  return starknet

def update_starknet_block(starknet, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
  starknet.state.state.block_info = BlockInfo(
    block_number=block_number,
    block_timestamp=block_timestamp,
    gas_price=0,
    sequencer_address=starknet.state.state.block_info.sequencer_address
  )

def reset_starknet_block(starknet):
  update_starknet_block(starknet=starknet)


@pytest.fixture
async def account_factory(get_starknet):
  starknet = get_starknet
  account = await deploy(starknet, "contracts/account/Account.cairo")
  await account.initialize(signer.public_key, guardian.public_key).invoke()
  return account


@pytest.fixture
async def dapp_factory(get_starknet):
  starknet = get_starknet
  dapp = await deploy(starknet, "contracts/test/dapp.cairo")
  return dapp


@pytest.mark.asyncio
async def test_initializer(account_factory):
  account = account_factory
  # should be configured correctly
  assert (await account.get_signer_public_key().call()).result.public_key == (signer.public_key)
  assert (await account.get_guardian_public_key().call()).result.public_key == (guardian.public_key)
  assert (await account.get_version().call()).result.version == VERSION
  assert (await account.supportsInterface(IACCOUNT_ID).call()).result.success == 1
  # should throw when calling initialize twice
  await assert_revert(
    account.initialize(signer.public_key, guardian.public_key).invoke(),
    "Account: already initialized"
  )


@pytest.mark.asyncio
async def test_call_dapp(account_factory, dapp_factory):
  account = account_factory
  dapp = dapp_factory
  sender = TransactionSender(account)

  calls = [(dapp.contract_address, 'set_number', [47])]

  # should revert with the wrong nonce
  await assert_revert(
    sender.send_transaction(calls, signer, nonce=3),
    "Account: invalid nonce"
  )

  # should revert with the wrong signer
  await assert_revert(
    sender.send_transaction(calls, wrong_signer),
    "Account: invalid signer signature"
  )

  # should call the dapp
  assert (await dapp.get_number(account.contract_address).call()).result.number == 0

  tx_exec_info = await sender.send_transaction(calls, signer)

  assert_event_emmited(
    tx_exec_info,
    from_address=account.contract_address,
    name='TransactionExecuted'
  )

  assert (await dapp.get_number(account.contract_address).call()).result.number == 47


@pytest.mark.asyncio
async def test_multicall(account_factory, dapp_factory):
  account = account_factory
  dapp = dapp_factory
  sender = TransactionSender(account)

  # should reverts when one of the call is to the account
  await assert_revert(
    sender.send_transaction([
      (dapp.contract_address, 'set_number', [47]),
      (account.contract_address, 'set_signer_public_key', [1])
    ], signer)
  )

  await assert_revert(
    sender.send_transaction([
      (account.contract_address, 'set_signer_public_key', [1]),
      (dapp.contract_address, 'set_number', [47])
    ], signer)
  )

  # should call the dapp
  assert (await dapp.get_number(account.contract_address).call()).result.number == 0

  await sender.send_transaction([
    (dapp.contract_address, 'set_number', [47]),
    (dapp.contract_address, 'increase_number', [10])
  ], signer)

  assert (await dapp.get_number(account.contract_address).call()).result.number == 57


@pytest.mark.asyncio
async def test_change_signer(account_factory):
  account = account_factory
  sender = TransactionSender(account)
  new_signer = Signer(4444444444)

  assert (await account.get_signer_public_key().call()).result.public_key == (signer.public_key)

  # should revert with the wrong signer
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'set_signer_public_key', [new_signer.public_key])], wrong_signer),
    "Account: invalid signer signature"
  )

  # should work with the correct signers
  tx_exec_info = await sender.send_transaction([(account.contract_address, 'set_signer_public_key', [new_signer.public_key])], signer)

  assert_event_emmited(
    tx_exec_info,
    from_address=account.contract_address,
    name='SignerPublicKeyChanged',
    data=[new_signer.public_key]
  )

  assert (await account.get_signer_public_key().call()).result.public_key == (new_signer.public_key)


@pytest.mark.asyncio
async def test_change_guardian(account_factory):
  account = account_factory
  sender = TransactionSender(account)
  new_guardian = Signer(55555555)

  assert (await account.get_guardian_public_key().call()).result.public_key == (guardian.public_key)

  # should revert with the wrong signer
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'set_guardian_public_key', [new_guardian.public_key])], wrong_signer),
    "Account: invalid signer signature"
  )

  # should work with the correct signers
  tx_exec_info = await sender.send_transaction([(account.contract_address, 'set_guardian_public_key', [new_guardian.public_key])], signer)

  assert_event_emmited(
    tx_exec_info,
    from_address=account.contract_address,
    name='GuardianPublicKeyChanged',
    data=[new_guardian.public_key]
  )

  assert (await account.get_guardian_public_key().call()).result.public_key == (new_guardian.public_key)


@pytest.mark.asyncio
async def test_trigger_escape_signer_by_guardian(get_starknet, account_factory):
  account = account_factory
  starknet = get_starknet
  sender = TransactionSender(account)

  # reset block_timestamp
  reset_starknet_block(starknet=starknet)

  escape = (await account.get_signer_escape().call()).result
  assert (escape.active_at == 0)

  # should revert with the wrong guardian
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'trigger_signer_escape', [])], wrong_guardian),
    "Account: invalid guardian signature"
  )

  tx_exec_info = await sender.send_transaction([(account.contract_address, 'trigger_signer_escape', [])], guardian)

  assert_event_emmited(
    tx_exec_info,
    from_address=account.contract_address,
    name='SignerEscapeTriggered',
    data=[DEFAULT_TIMESTAMP + ESCAPE_SECURITY_PERIOD]
  )

  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == (DEFAULT_TIMESTAMP + ESCAPE_SECURITY_PERIOD)


@pytest.mark.asyncio
async def test_escape_signer(get_starknet, account_factory):
  account = account_factory
  starknet = get_starknet
  sender = TransactionSender(account)
  new_signer = Signer(5555555578895)

  # reset block_timestamp
  reset_starknet_block(starknet=starknet)

  # trigger escape
  await sender.send_transaction([(account.contract_address, 'trigger_signer_escape', [])], guardian)
  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == (DEFAULT_TIMESTAMP + ESCAPE_SECURITY_PERIOD)

  # should fail to escape before the end of the period
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'escape_signer', [new_signer.public_key])], guardian),
    "Account: invalid escape"
  )

  # should revert with the wrong guardian
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'escape_signer', [new_signer.public_key])], wrong_guardian),
    "Account: invalid guardian signature"
  )

  # wait security period
  update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP+ESCAPE_SECURITY_PERIOD))

  # should escape after the security period
  assert (await account.get_signer_public_key().call()).result.public_key == (signer.public_key)
  tx_exec_info = await sender.send_transaction([(account.contract_address, 'escape_signer', [new_signer.public_key])], guardian)

  assert_event_emmited(
    tx_exec_info,
    from_address=account.contract_address,
    name='SignerEscaped',
    data=[new_signer.public_key]
  )

  assert (await account.get_signer_public_key().call()).result.public_key == (new_signer.public_key)

  # escape should be cleared
  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == 0


@pytest.mark.asyncio
async def test_guardian_overrides_trigger_escape_signer(get_starknet, account_factory):
  account = account_factory
  starknet = get_starknet
  sender = TransactionSender(account)
  new_signer = Signer(5555555578895)

  # reset block_timestamp
  reset_starknet_block(starknet=starknet)

  # trigger escape
  await sender.send_transaction([(account.contract_address, 'trigger_signer_escape', [])], guardian)
  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == (DEFAULT_TIMESTAMP + ESCAPE_SECURITY_PERIOD)

  # wait few seconds
  update_starknet_block(starknet=starknet, block_timestamp=(DEFAULT_TIMESTAMP+100))

  # signer overrides escape
  await sender.send_transaction([(account.contract_address, 'trigger_signer_escape', [])], guardian)
  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == (DEFAULT_TIMESTAMP + 100 + ESCAPE_SECURITY_PERIOD)


@pytest.mark.asyncio
async def test_cancel_escape(get_starknet, account_factory):
  account = account_factory
  starknet = get_starknet
  sender = TransactionSender(account)

  # reset block_timestamp
  reset_starknet_block(starknet=starknet)

  # trigger escape
  await sender.send_transaction([(account.contract_address, 'trigger_signer_escape', [])], guardian)
  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == (DEFAULT_TIMESTAMP + ESCAPE_SECURITY_PERIOD)

  # should fail to cancel with the guardian
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'cancel_escape', [])], guardian),
    "Account: invalid signer signature"
  )

  # cancel escape
  tx_exec_info = await sender.send_transaction([(account.contract_address, 'cancel_escape', [])], signer)

  assert_event_emmited(
    tx_exec_info,
    from_address=account.contract_address,
    name='EscapeCanceled',
    data=[]
  )

  # escape should be cleared
  escape = (await account.get_signer_escape().call()).result
  assert escape.active_at == 0


@pytest.mark.asyncio
async def test_is_valid_signature(account_factory):
  account = account_factory
  hash = 1283225199545181604979924458180358646374088657288769423115053097913173815464

  signature = list(signer.sign(hash))

  res = (await account.is_valid_signature(hash, signature).call()).result
  assert (res.is_valid == 1)
