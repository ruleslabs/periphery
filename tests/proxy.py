import pytest
import asyncio

from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from starkware.starknet.compiler.compile import get_selector_from_name

from utils.Signer import Signer
from utils.misc import deploy, declare, deploy_proxy, assert_revert, str_to_felt, assert_event_emmited
from utils.TransactionSender import TransactionSender

signer = Signer(123456789987654321)
guardian = Signer(456789987654321123)
wrong_signer = Signer(666666666666666666)
wrong_guardian = Signer(6767676767)

VERSION = str_to_felt('0.1.0')


@pytest.fixture(scope='module')
def event_loop():
  return asyncio.new_event_loop()


@pytest.fixture(scope='module')
async def get_starknet():
  starknet = await Starknet.empty()
  return starknet


@pytest.fixture
async def account_factory(get_starknet):
  starknet = get_starknet
  account = await deploy(starknet, "contracts/account/Account.cairo")
  await account.initialize(signer.public_key, guardian.public_key).invoke()
  return account


@pytest.fixture
async def account_factory(get_starknet):
  starknet = get_starknet
  implementation_class = await declare(starknet, "contracts/account/Account.cairo")
  proxy, account = await deploy_proxy(
    starknet,
    "contracts/proxy/Proxy.cairo",
    implementation_class.abi,
    [implementation_class.class_hash, get_selector_from_name('initialize'), 2, signer.public_key, guardian.public_key],
  )
  return account, proxy, implementation_class.class_hash


@pytest.fixture
async def dapp_factory(get_starknet):
    starknet = get_starknet
    dapp_class = await declare(starknet, "contracts/test/dapp.cairo")
    dapp = await deploy(starknet, "contracts/test/dapp.cairo")
    return dapp, dapp_class.class_hash


@pytest.mark.asyncio
async def test_initializer(account_factory):
  account, proxy, implementation = account_factory
  assert (await proxy.get_implementation().call()).result.implementation == implementation
  assert (await account.get_signer_public_key().call()).result.public_key == signer.public_key
  assert (await account.get_guardian_public_key().call()).result.public_key == guardian.public_key
  assert (await account.get_version().call()).result.version == VERSION


@pytest.mark.asyncio
async def test_call_dapp(account_factory, dapp_factory):
  account, _, _ = account_factory
  dapp, _ = dapp_factory
  sender = TransactionSender(account)

  # should revert with the wrong signer
  await assert_revert(
    sender.send_transaction([(dapp.contract_address, 'set_number', [47])], wrong_signer),
    "Account: invalid signer signature"
  )

  # should call the dapp
  assert (await dapp.get_number(account.contract_address).call()).result.number == 0
  await sender.send_transaction([(dapp.contract_address, 'set_number', [47])], signer)
  assert (await dapp.get_number(account.contract_address).call()).result.number == 47

@pytest.mark.asyncio
async def test_upgrade(account_factory, dapp_factory):
  account, proxy, account_impl_1 = account_factory
  _, _, account_impl_2 = account_factory
  dapp, dapp_class_hash = dapp_factory

  sender = TransactionSender(account)

  # should revert with the wrong guardian
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'upgrade', [account_impl_2])], wrong_signer),
    "Account: invalid signer signature"
  )

  # should revert when the target is not an account
  await assert_revert(
    sender.send_transaction([(account.contract_address, 'upgrade', [dapp_class_hash])], signer),
    "Account: invalid implementation",
    StarknetErrorCode.ENTRY_POINT_NOT_FOUND_IN_CONTRACT
  )

  assert (await proxy.get_implementation().call()).result.implementation == (account_impl_1)

  tx_exec_info = await sender.send_transaction([(account.contract_address, 'upgrade', [account_impl_2])], signer)

  assert_event_emmited(
      tx_exec_info,
      from_address=account.contract_address,
      name='AccountUpgraded',
      data=[account_impl_2]
  )

  assert (await proxy.get_implementation().call()).result.implementation == (account_impl_2)
