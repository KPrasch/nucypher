

from nucypher.blockchain.eth.agents import ContractAgency, PREApplicationAgent
from tests.constants import PYEVM_DEV_URI


def test_get_agent_with_different_registries(application_economics, test_registry, agency_local_registry):
    # Get agents using same registry instance
    application_agent_1 = ContractAgency.get_agent(
        PREApplicationAgent, registry=test_registry, eth_provider_uri=PYEVM_DEV_URI
    )
    application_agent_2 = ContractAgency.get_agent(
        PREApplicationAgent, registry=test_registry, eth_provider_uri=PYEVM_DEV_URI
    )
    assert application_agent_2.registry == application_agent_1.registry == test_registry
    assert application_agent_2 is application_agent_1

    # Same content but different classes of registries
    application_agent_2 = ContractAgency.get_agent(
        PREApplicationAgent,
        registry=agency_local_registry,
        eth_provider_uri=PYEVM_DEV_URI,
    )
    assert application_agent_2.registry == test_registry
    assert application_agent_2 is application_agent_1
