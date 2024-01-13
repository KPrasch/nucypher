from pathlib import Path
from typing import Iterable, Optional

import pytest

from nucypher.blockchain.eth.actors import Operator
from nucypher.blockchain.eth.agents import (
    ContractAgency,
    CoordinatorAgent,
    StakingProvidersReservoir,
    TACoApplicationAgent,
    TACoChildApplicationAgent,
)
from nucypher.blockchain.eth.clients import EthereumClient
from nucypher.blockchain.eth.interfaces import (
    BlockchainInterface,
    BlockchainInterfaceFactory,
)
from nucypher.blockchain.eth.registry import (
    ContractRegistry,
)
from nucypher.characters.lawful import Ursula
from nucypher.cli.types import ChecksumAddress
from nucypher.config.characters import UrsulaConfiguration
from nucypher.network.nodes import Teacher
from tests.constants import (
    KEYFILE_NAME_TEMPLATE,
    TEMPORARY_DOMAIN,
    TESTERCHAIN_CHAIN_ID,
)
from tests.mock.interfaces import MockBlockchain
from tests.mock.io import MockStdinWrapper
from tests.utils.blockchain import ReservedTestAccountManager, TestAccount
from tests.utils.registry import MockRegistrySource, mock_registry_sources
from tests.utils.ursula import (
    mock_permitted_multichain_connections,
    setup_multichain_ursulas,
)


def pytest_addhooks(pluginmanager):
    pluginmanager.set_blocked("ape_test")


@pytest.fixture(scope="module", autouse=True)
def mock_sample_reservoir(accounts, mock_contract_agency):
    def mock_reservoir(
        without: Optional[Iterable[ChecksumAddress]] = None, *args, **kwargs
    ):
        addresses = {
            wallet.address: 1
            for wallet in accounts.stake_provider_wallets
            if wallet.address not in without
        }
        return StakingProvidersReservoir(addresses)

    mock_agent = mock_contract_agency.get_agent(TACoApplicationAgent)
    mock_agent.get_staking_provider_reservoir = mock_reservoir


@pytest.fixture(scope="function", autouse=True)
def mock_taco_application_agent(testerchain, mock_contract_agency):
    mock_agent = mock_contract_agency.get_agent(TACoApplicationAgent)
    yield mock_agent
    mock_agent.reset()


@pytest.fixture(scope="function", autouse=True)
def mock_taco_child_application_agent(testerchain, mock_contract_agency):
    mock_agent = mock_contract_agency.get_agent(TACoChildApplicationAgent)
    yield mock_agent
    mock_agent.reset()


@pytest.fixture(scope="function", autouse=True)
def mock_coordinator_agent(testerchain, mock_contract_agency):
    from tests.mock.coordinator import MockCoordinatorAgent

    mock_agent = MockCoordinatorAgent(blockchain=testerchain)
    mock_contract_agency._MockContractAgency__agents[CoordinatorAgent] = mock_agent
    yield mock_agent
    mock_agent.reset()


@pytest.fixture(scope="function")
def mock_stdin(mocker):
    mock = MockStdinWrapper()

    mocker.patch("sys.stdin", new=mock.mock_stdin)
    mocker.patch("getpass.getpass", new=mock.mock_getpass)

    yield mock

    # Sanity check.
    # The user is encouraged to `assert mock_stdin.empty()` explicitly in the test
    # right after the input-consuming function call.
    assert (
        mock.empty()
    ), "Stdin mock was not empty on teardown - some unclaimed input remained"


@pytest.fixture(scope="module")
def testerchain(mock_testerchain, module_mocker) -> MockBlockchain:
    def always_use_mock(*a, **k):
        return mock_testerchain

    module_mocker.patch.object(
        BlockchainInterfaceFactory, "get_interface", always_use_mock
    )
    return mock_testerchain


@pytest.fixture(scope="module", autouse=True)
def mock_interface(module_mocker):
    # Generic Interface
    mock_transaction_sender = module_mocker.patch.object(
        BlockchainInterface, "sign_and_broadcast_transaction"
    )
    mock_transaction_sender.return_value = MockBlockchain.FAKE_RECEIPT
    return mock_transaction_sender


@pytest.fixture(scope="module")
def test_registry(module_mocker):
    with mock_registry_sources(mocker=module_mocker):
        mock_source = MockRegistrySource(domain=TEMPORARY_DOMAIN)
        registry = ContractRegistry(source=mock_source)
        yield registry


@pytest.fixture(scope="module", autouse=True)
def mock_contract_agency():
    # Patch
    from tests.mock.agents import MockContractAgency

    # Monkeypatch # TODO: Use better tooling for this monkeypatch?
    get_agent = ContractAgency.get_agent
    get_agent_by_name = ContractAgency.get_agent_by_contract_name
    ContractAgency.get_agent = MockContractAgency.get_agent
    ContractAgency.get_agent_by_contract_name = (
        MockContractAgency.get_agent_by_contract_name
    )

    # Test
    yield MockContractAgency()

    # Restore the monkey patching
    ContractAgency.get_agent = get_agent
    ContractAgency.get_agent_by_contract_name = get_agent_by_name


@pytest.fixture(scope="module")
def agency(mock_contract_agency):
    yield mock_contract_agency


@pytest.fixture(scope="function")
def mock_funding_and_bonding(
    accounts, mocker, mock_taco_application_agent, mock_taco_child_application_agent
):
    # funding
    mocker.patch.object(EthereumClient, "get_balance", return_value=1)

    # bonding
    staking_provider = accounts.stake_provider_wallets[0].address
    mock_taco_application_agent.get_staking_provider_from_operator.return_value = (
        staking_provider
    )
    mock_taco_child_application_agent.staking_provider_from_operator.return_value = (
        staking_provider
    )


@pytest.fixture(scope="module")
def mock_accounts():
    accounts = dict()
    for i in range(ReservedTestAccountManager.NUMBER_OF_URSULAS_IN_TESTS):
        account = TestAccount.random()
        filename = KEYFILE_NAME_TEMPLATE.format(month=i + 1, address=account.address)
        accounts[filename] = account
    return accounts


@pytest.fixture(scope="module")
def mock_account(mock_accounts):
    return list(mock_accounts.items())[0][1]


@pytest.fixture(scope="module")
def operator_account(mock_accounts, testerchain):
    account = list(mock_accounts.values())[0]
    return account


@pytest.fixture(scope="module")
def operator_address(operator_account):
    address = operator_account.address
    return address


@pytest.fixture(scope="module")
def custom_config_filepath(custom_filepath: Path):
    filepath = custom_filepath / UrsulaConfiguration.generate_filename()
    return filepath


@pytest.fixture(scope="module", autouse=True)
def mock_substantiate_stamp(module_mocker, monkeymodule):
    fake_signature = b"\xb1W5?\x9b\xbaix>'\xfe`\x1b\x9f\xeb*9l\xc0\xa7\xb9V\x9a\x83\x84\x04\x97\x0c\xad\x99\x86\x81W\x93l\xc3\xbde\x03\xcd\"Y\xce\xcb\xf7\x02z\xf6\x9c\xac\x84\x05R\x9a\x9f\x97\xf7\xa02\xb2\xda\xa1Gv\x01"
    module_mocker.patch.object(Ursula, "_substantiate_stamp", autospec=True)
    module_mocker.patch.object(Ursula, "operator_signature", fake_signature)
    module_mocker.patch.object(Teacher, "validate_operator")


@pytest.fixture(scope="module")
def real_operator_get_staking_provider_address():
    _real_get_staking_provider_address = Operator.get_staking_provider_address
    return _real_get_staking_provider_address


@pytest.mark.usefixtures("monkeymodule")
@pytest.fixture(scope="module", autouse=True)
def bond_operators(real_operator_get_staking_provider_address, accounts):
    def faked(self, *args, **kwargs):
        return accounts.stake_provider_wallets[
            accounts.ursula_wallets.index(self.wallet)
        ].address

    Operator.get_staking_provider_address = faked


@pytest.fixture(scope="module")
def monkeypatch_get_staking_provider_from_operator(monkeymodule):
    monkeymodule.setattr(
        Operator,
        "get_staking_provider_address",
        lambda self: self.wallet.address,
    )


@pytest.fixture(scope="module", autouse=True)
def mock_condition_blockchains(module_mocker):
    """adds testerchain's chain ID to permitted conditional chains"""
    module_mocker.patch.dict(
        "nucypher.policy.conditions.evm._CONDITION_CHAINS",
        {TESTERCHAIN_CHAIN_ID: "eth-tester/pyevm"},
    )


@pytest.fixture(scope="module")
def multichain_ids(module_mocker):
    ids = mock_permitted_multichain_connections(mocker=module_mocker)
    return ids


@pytest.fixture(scope="module")
def multichain_ursulas(ursulas, multichain_ids):
    setup_multichain_ursulas(ursulas=ursulas, chain_ids=multichain_ids)
    return ursulas
