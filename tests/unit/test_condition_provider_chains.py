import pytest

from nucypher.blockchain.eth import domains
from nucypher.blockchain.eth.actors import Operator


class TestConditionProviderChainValidation:
    @pytest.fixture
    def mock_operator(self, mocker):
        operator = mocker.Mock(spec=Operator)
        operator.domain = domains.MAINNET
        operator.ActorError = Operator.ActorError
        operator.log = mocker.Mock()
        return operator

    def test_missing_mandatory_chain_raises_error(self, mock_operator):
        endpoints = {1: ["http://eth.example.com"]}
        with pytest.raises(Operator.ActorError, match="missing mandatory chains"):
            Operator.get_condition_provider_manager(mock_operator, endpoints)

    def test_additional_chains_pass_validation(self, mock_operator, mocker):
        endpoints = {1: ["http://eth"], 137: ["http://poly"], 8453: ["http://base"]}

        mocker.patch(
            "nucypher.blockchain.eth.actors.rpc_endpoint_health_check",
            return_value=True,
        )
        mocker.patch(
            "nucypher.blockchain.eth.actors.get_healthy_default_rpc_endpoints",
            return_value={},
        )
        Operator.get_condition_provider_manager(mock_operator, endpoints)
