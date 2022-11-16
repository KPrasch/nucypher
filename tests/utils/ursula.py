

import contextlib
import socket
from typing import Iterable, List, Optional, Set

from cryptography.x509 import Certificate

from nucypher.blockchain.eth.interfaces import BlockchainInterface
from nucypher.characters.lawful import Ursula
from nucypher.config.characters import UrsulaConfiguration
from tests.constants import NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK


def select_test_port() -> int:
    """
    Search for a network port that is open at the time of the call;
    Verify that the port is not the same as the default Ursula running port.

    Note: There is no guarantee that the returned port will still be available later.
    """

    closed_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with contextlib.closing(closed_socket) as open_socket:
        open_socket.bind(('localhost', 0))
        port = open_socket.getsockname()[1]

        if port == UrsulaConfiguration.DEFAULT_REST_PORT or port > 64000:
            return select_test_port()

        open_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return port


def make_federated_ursulas(ursula_config: UrsulaConfiguration,
                           quantity: int = NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK,
                           know_each_other: bool = True,
                           **ursula_overrides) -> Set[Ursula]:

    if not MOCK_KNOWN_URSULAS_CACHE:
        starting_port = MOCK_URSULA_STARTING_PORT
    else:
        starting_port = max(MOCK_KNOWN_URSULAS_CACHE.keys()) + 1

    federated_ursulas = set()
    for port in range(starting_port, starting_port+quantity):
        ursula = ursula_config.produce(rest_port=port + 100,
                                       **ursula_overrides)

        federated_ursulas.add(ursula)

        # Store this Ursula in our global testing cache.
        port = ursula.rest_interface.port
        MOCK_KNOWN_URSULAS_CACHE[port] = ursula

    if know_each_other:
        for ursula_to_teach in federated_ursulas:
            # Add other Ursulas as known nodes.
            for ursula_to_learn_about in federated_ursulas:
                ursula_to_teach.remember_node(ursula_to_learn_about)

    return federated_ursulas


def make_decentralized_ursulas(ursula_config: UrsulaConfiguration,
                               staking_provider_addresses: Iterable[str],
                               operator_addresses: Iterable[str],
                               commit_now=True,
                               **ursula_overrides) -> List[Ursula]:

    if not MOCK_KNOWN_URSULAS_CACHE:
        starting_port = MOCK_URSULA_STARTING_PORT
    else:
        starting_port = max(MOCK_KNOWN_URSULAS_CACHE.keys()) + 1

    providers_and_operators = zip(staking_provider_addresses, operator_addresses)
    ursulas = list()

    for port, (staking_provider_address, operator_address) in enumerate(providers_and_operators, start=starting_port):
        ursula = ursula_config.produce(checksum_address=staking_provider_address,
                                       operator_address=operator_address,
                                       rest_port=port + 100,
                                       **ursula_overrides)

        # TODO: Confirm operator here?
        # if commit_now:
        #     ursula.confirm_operator_address()

        ursulas.append(ursula)

        # Store this Ursula in our global testing cache.
        port = ursula.rest_interface.port
        MOCK_KNOWN_URSULAS_CACHE[port] = ursula

    return ursulas


def make_ursula_for_staking_provider(staking_provider,
                                     operator_address: str,
                                     blockchain: BlockchainInterface,
                                     ursula_config: UrsulaConfiguration,
                                     ursulas_to_learn_about: Optional[List[Ursula]] = None,
                                     **ursula_overrides) -> Ursula:

    # Assign worker to this staking provider
    staking_provider.bond_worker(operator_address=operator_address)

    worker = make_decentralized_ursulas(ursula_config=ursula_config,
                                        blockchain=blockchain,
                                        staking_provider_addresses=[staking_provider.checksum_address],
                                        operator_addresses=[operator_address],
                                        **ursula_overrides).pop()

    for ursula_to_learn_about in (ursulas_to_learn_about or []):
        worker.remember_node(ursula_to_learn_about)
        ursula_to_learn_about.remember_node(worker)

    return worker


def start_pytest_ursula_services(ursula: Ursula) -> Certificate:
    """
    Takes an ursula and starts its learning
    services when running tests with pytest twisted.
    """

    node_deployer = ursula.get_deployer()

    node_deployer.addServices()
    node_deployer.catalogServers(node_deployer.hendrix)
    node_deployer.start()

    certificate_as_deployed = node_deployer.cert.to_cryptography()
    return certificate_as_deployed


MOCK_KNOWN_URSULAS_CACHE = dict()
MOCK_URSULA_STARTING_PORT = 51000  # select_test_port()
