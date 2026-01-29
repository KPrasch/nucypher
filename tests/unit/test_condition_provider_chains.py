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

        # Track which URI is being processed to return correct chain_id
        uri_to_chain = {
            "http://eth": 1,
            "http://poly": 137,
            "http://base": 8453,
        }
        current_chain_id = [None]  # Use list to allow mutation in closure

        def make_provider_side_effect(uri):
            current_chain_id[0] = uri_to_chain[uri]
            return mocker.Mock()

        mock_operator._make_condition_provider.side_effect = make_provider_side_effect

        def web3_factory(provider):
            mock_web3 = mocker.Mock()
            mock_web3.eth.chain_id = current_chain_id[0]
            return mock_web3

        mocker.patch(
            "nucypher.blockchain.eth.actors.Web3",
            side_effect=web3_factory,
        )
        mocker.patch(
            "nucypher.blockchain.eth.actors.rpc_endpoint_health_check",
            return_value=True,
        )
        mocker.patch(
            "nucypher.blockchain.eth.actors.get_healthy_default_rpc_endpoints",
            return_value={},
        )
        Operator.get_condition_provider_manager(mock_operator, endpoints)
