import os

import pytest
from eth_utils import is_checksum_address
from eth_utils import to_checksum_address

from nucypher.blockchain.eth.actors import Administrator
from nucypher.blockchain.eth.interfaces import BlockchainInterface, BlockchainDeployerInterface
from nucypher.blockchain.eth.registry import InMemoryContractRegistry
from nucypher.crypto.api import verify_eip_191


#
# NOTE: This module is skipped on CI
#
from nucypher.utilities.sandbox.constants import INSECURE_DEVELOPMENT_PASSWORD


def test_geth_EIP_191_client_signature_integration(instant_geth_dev_node):

    # TODO: Move to decorator
    if 'CIRCLECI' in os.environ:
        pytest.skip("Do not run Geth nodes in CI")

    # Start a geth process
    blockchain = BlockchainInterface(provider_process=instant_geth_dev_node)
    blockchain.connect(fetch_registry=False, sync_now=False)

    # Sign a message (RPC) and verify it.
    etherbase = blockchain.client.accounts[0]
    stamp = b'STAMP-' + os.urandom(64)
    signature = blockchain.client.sign_message(account=etherbase, message=stamp)
    is_valid = verify_eip_191(address=etherbase,
                              signature=signature,
                              message=stamp)
    assert is_valid


def test_geth_create_new_account(instant_geth_dev_node):

    # TODO: Move to decorator
    if 'CIRCLECI' in os.environ:
        pytest.skip("Do not run Geth nodes in CI")

    blockchain = BlockchainInterface(provider_process=instant_geth_dev_node)
    blockchain.connect(fetch_registry=False, sync_now=False)
    new_account = blockchain.client.new_account(password=INSECURE_DEVELOPMENT_PASSWORD)
    assert is_checksum_address(new_account)


def test_geth_deployment_integration(instant_geth_dev_node):

    # TODO: Move to decorator
    if 'CIRCLECI' in os.environ:
        pytest.skip("Do not run Geth nodes in CI")

    memory_registry = InMemoryContractRegistry()
    blockchain = BlockchainDeployerInterface(provider_process=instant_geth_dev_node, registry=memory_registry)

    # Make Deployer
    etherbase = to_checksum_address(instant_geth_dev_node.accounts[0].decode())  # TODO: Make property on nucypher geth node instances?
    deployer = Administrator(blockchain=blockchain,
                             deployer_address=etherbase,
                             client_password=None)  # dev accounts have no password.

    assert int(deployer.blockchain.client.chain_id) == 1337

    # Deploy
    secrets = dict()
    for deployer_class in deployer.upgradeable_deployer_classes:
        secrets[deployer_class.contract_name] = INSECURE_DEVELOPMENT_PASSWORD

    deployer.deploy_network_contracts(secrets=secrets, interactive=False)
