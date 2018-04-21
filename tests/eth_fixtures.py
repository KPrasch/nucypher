import os
import tempfile
from os.path import abspath, dirname

import pytest
import shutil
from eth_tester import EthereumTester, PyEVMBackend
from geth import DevGethProcess, LoggingMixin
from web3 import EthereumTesterProvider, IPCProvider
from web3.middleware import geth_poa_middleware

from nkms.blockchain.eth.agents import NuCypherKMSTokenAgent, MinerAgent
from nkms.blockchain.eth.agents import PolicyAgent
from nkms.blockchain.eth.chains import TheBlockchain, TesterBlockchain
from nkms.blockchain.eth.deployers import PolicyManagerDeployer, NuCypherKMSTokenDeployer
from nkms.blockchain.eth.interfaces import Registrar, ContractProvider
from nkms.blockchain.eth.sol.compile import SolidityCompiler
from nkms.blockchain.eth.utilities import MockMinerEscrowDeployer
from tests.blockchain.eth import contracts


@pytest.fixture(scope='session')
def solidity_compiler():
    test_contracts_dir = os.path.join(dirname(abspath(contracts.__file__)), 'contracts')
    compiler = SolidityCompiler(test_contract_dir=test_contracts_dir)
    yield compiler


@pytest.fixture(scope='module')
def registrar():
    _, filepath = tempfile.mkstemp()
    registrar = Registrar(chain_name='tester', registrar_filepath=filepath)
    yield registrar
    os.remove(filepath)


@pytest.fixture(scope='module')
def geth_ipc_provider(registrar, solidity_compiler):
    """
    Provider backend
    https:// github.com/ethereum/eth-tester
    """

    ipc_provider = IPCProvider(ipc_path='/tmp/geth.ipc')
    tester_provider = ContractProvider(provider_backend=ipc_provider,
                                       registrar=registrar,
                                       sol_compiler=solidity_compiler)

    tester_provider.w3.middleware_stack.inject(geth_poa_middleware, layer=0)

    # Generate 9 additional unlocked accounts with 1M ether each
    insecure_passphrase = 'this-is-not-a-secure-password'
    for _ in range(9):
        address = tester_provider.w3.personal.newAccount(insecure_passphrase)
        tester_provider.w3.personal.unlockAccount(address, passphrase=insecure_passphrase)

        tx = {'to': address,
              'from': tester_provider.w3.eth.coinbase,
              'value': 1000000 * 10 ** 18}
        _txhash = tester_provider.w3.eth.sendTransaction(tx)

    yield tester_provider


@pytest.fixture(scope='module')
def auto_geth_ipc_provider(registrar, solidity_compiler):
    """
    Provider backend
    https: // github.com / ethereum / eth - tester     # available-backends
    """

    #
    # spin-up geth
    #

    testing_dir = tempfile.mkdtemp()
    chain_name = 'nkms_tester'

    class NKMSGeth(LoggingMixin, DevGethProcess):
        pass

    geth = DevGethProcess(chain_name=chain_name, base_dir=testing_dir)
    geth.start()

    geth.wait_for_ipc(timeout=30)
    geth.wait_for_dag(timeout=120)
    assert geth.is_dag_generated
    assert geth.is_running
    assert geth.is_alive

    ipc_provider = IPCProvider(ipc_path=os.path.join(testing_dir, chain_name, 'geth.ipc'))
    tester_provider = ContractProvider(provider_backend=ipc_provider,
                                       registrar=registrar,
                                       sol_compiler=solidity_compiler)

    tester_provider.w3.middleware_stack.inject(geth_poa_middleware, layer=0)

    # Generate 9 additional unlocked accounts with 1M ether each
    insecure_passphrase = 'this-is-not-a-secure-password'
    for _ in range(9):
        address = tester_provider.w3.personal.newAccount(insecure_passphrase)
        tester_provider.w3.personal.unlockAccount(address, insecure_passphrase)

        tx = {'to': address,
              'from': tester_provider.w3.eth.coinbase,
              'value': 1000000}

        _txhash = tester_provider.w3.eth.sendTransaction(tx)

    assert len(geth.accounts) == 10
    yield tester_provider

    #
    # Teardown
    #
    geth.stop()
    assert geth.is_stopped
    assert not geth.is_alive
    shutil.rmtree(testing_dir)


@pytest.fixture(scope='module')
def pyevm_provider(registrar, solidity_compiler):
    """
    Provider backend
    https: // github.com / ethereum / eth - tester     # available-backends
    """
    eth_tester = EthereumTester(backend=PyEVMBackend(), auto_mine_transactions=True)
    test_provider = EthereumTesterProvider(ethereum_tester=eth_tester)

    tester_provider = ContractProvider(provider_backend=test_provider,
                                       registrar=registrar,
                                       sol_compiler=solidity_compiler)
    yield tester_provider


@pytest.fixture(scope='module')
def web3(geth_ipc_provider):
    yield geth_ipc_provider.w3


@pytest.fixture(scope='module')
def chain(geth_ipc_provider):
    chain = TesterBlockchain(contract_provider=geth_ipc_provider)
    yield chain

    del chain
    TheBlockchain._TheBlockchain__instance = None


# 
# API #
# 


@pytest.fixture()
def mock_token_deployer(chain):
    token_deployer = NuCypherKMSTokenDeployer(blockchain=chain)
    token_deployer.arm()
    token_deployer.deploy()
    yield token_deployer


@pytest.fixture()
def mock_miner_escrow_deployer(token_agent):
    escrow = MockMinerEscrowDeployer(token_agent=token_agent)
    escrow.arm()
    escrow.deploy()
    yield escrow


@pytest.fixture()
def mock_policy_manager_deployer(mock_miner_escrow_deployer):
    policy_manager_deployer = PolicyManagerDeployer(miner_agent=mock_token_deployer)
    policy_manager_deployer.arm()
    policy_manager_deployer.deploy()
    yield policy_manager_deployer


#
# Unused args preserve fixture dependency order #
#

@pytest.fixture()
def token_agent(chain, mock_token_deployer):
    token = NuCypherKMSTokenAgent(blockchain=chain)
    yield token


@pytest.fixture()
def mock_miner_agent(token_agent, mock_token_deployer, mock_miner_escrow_deployer):
    miner_agent = MinerAgent(token_agent=token_agent)
    yield miner_agent


@pytest.fixture()
def mock_policy_agent(mock_miner_agent, token_agent, mock_token_deployer, mock_miner_escrow_deployer):
    policy_agent = PolicyAgent(miner_agent=mock_miner_agent)
    yield policy_agent


# @pytest.fixture()
# def token(web3, chain):
#     creator = web3.eth.accounts[0]
#     # Create an ERC20 token
#     token, _ = chain.provider.get_or_deploy_contract('NuCypherKMSToken', int(2e9))
#     return token

#
# @pytest.fixture()
# def escrow_contract(web3, chain, token):
#     creator = web3.eth.accounts[0]
#     # Creator deploys the escrow
#
#     contract, _ = chain.provider.get_or_deploy_contract(
#         'MinersEscrow', token.address, 1, int(8e7), 4, 4, 2, 100, int(1e9)
#     )
#
#     dispatcher, _ = chain.provider.deploy_contract('Dispatcher', contract.address)
#
#     # Deploy second version of the government contract
#     contract = web3.eth.contract(contract.abi, dispatcher.address, ContractFactoryClass=Contract)
#     return contract
