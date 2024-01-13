import time
from unittest import mock

import pytest_twisted as pt
from twisted.internet import threads

from nucypher.blockchain.eth.actors import Operator
from nucypher.characters.base import Learner
from nucypher.cli.literature import MISSING_CONFIGURATION_FILE
from nucypher.cli.main import nucypher_cli
from nucypher.config.characters import UrsulaConfiguration
from nucypher.config.constants import (
    TEMPORARY_DOMAIN_NAME,
)
from nucypher.utilities.networking import LOOPBACK_ADDRESS
from tests.constants import (
    INSECURE_DEVELOPMENT_PASSWORD,
    TEST_ETH_PROVIDER_URI,
    TEST_POLYGON_PROVIDER_URI,
)
from tests.utils.ursula import select_test_port, start_pytest_ursula_services


def test_missing_configuration_file(click_runner):
    cmd_args = (
        "ursula",
        "run",
        "--host",
        '255.32.54.32',
        "--domain",
        TEMPORARY_DOMAIN_NAME,
    )
    result = click_runner.invoke(nucypher_cli, cmd_args, catch_exceptions=False)
    assert result.exit_code != 0
    configuration_type = UrsulaConfiguration.NAME
    assert MISSING_CONFIGURATION_FILE.format(
        name=configuration_type.capitalize(),
        init_command=f'{configuration_type} init'
    ) in result.output


@pt.inlineCallbacks
def test_ursula_run_with_prometheus_but_no_metrics_port(click_runner):
    args = (
        "ursula",
        "run",  # Stat Ursula Command
        "--debug",  # Display log output; Do not attach console
        "--dev",  # Run in development mode (local ephemeral node)
        "--dry-run",  # Disable twisted reactor in subprocess
        "--lonely",  # Do not load seednodes
        "--prometheus",  # Specify collection of prometheus metrics
        "--eth-endpoint",
        TEST_ETH_PROVIDER_URI,
        "--polygon-endpoint",
        TEST_POLYGON_PROVIDER_URI,
    )

    result = yield threads.deferToThread(
        click_runner.invoke, nucypher_cli, args, catch_exceptions=False
    )

    assert result.exit_code != 0
    expected_error = "Error: --metrics-port is required when using --prometheus"
    assert expected_error in result.output


@pt.inlineCallbacks
def test_run_lone_default_development_ursula(click_runner, ursulas, testerchain, mocker):
    mocker.patch.object(Operator, "block_until_ready", return_value=True)
    deploy_port = select_test_port()
    args = (
        "ursula",
        "run",  # Stat Ursula Command
        "--debug",  # Display log output; Do not attach console
        "--port",
        deploy_port,  # Network Port
        "--dev",  # Run in development mode (ephemeral node)
        "--dry-run",  # Disable twisted reactor in subprocess
        "--lonely",  # Do not load seednodes,
        "--eth-endpoint",
        TEST_ETH_PROVIDER_URI,
        "--polygon-endpoint",
        TEST_ETH_PROVIDER_URI,
    )

    result = yield threads.deferToThread(
        click_runner.invoke,
        nucypher_cli,
        args,
        catch_exceptions=False,
        input=INSECURE_DEVELOPMENT_PASSWORD + "\n" + INSECURE_DEVELOPMENT_PASSWORD + "\n",
    )

    time.sleep(Learner._SHORT_LEARNING_DELAY)
    assert result.exit_code == 0, result.output
    assert "Running" in result.output
    assert f"{LOOPBACK_ADDRESS}:{deploy_port}" in result.output

    reserved_ports = (UrsulaConfiguration.DEFAULT_REST_PORT, UrsulaConfiguration.DEFAULT_DEVELOPMENT_REST_PORT)
    assert deploy_port not in reserved_ports


@pt.inlineCallbacks
def test_ursula_learns_via_cli(click_runner, ursulas, testerchain, mocker):
    mocker.patch.object(Operator, "block_until_ready", return_value=True)

    # Establish a running Teacher Ursula
    peer = list(ursulas)[0]
    peer_uri = peer.seed_node_metadata(as_peer_uri=True)
    deploy_port = select_test_port()

    def run_ursula():
        start_pytest_ursula_services(ursula=peer)
        args = (
            "ursula",
            "run",
            "--debug",  # Display log output; Do not attach console
            "--port",
            deploy_port,  # Network Port
            "--peer",
            peer_uri,
            "--dev",  # Run in development mode (ephemeral node)
            "--dry-run",  # Disable twisted reactor
            "--eth-endpoint",
            TEST_ETH_PROVIDER_URI,
            "--polygon-endpoint",
            TEST_ETH_PROVIDER_URI,
            '--peer',
            ursulas[0].seed_node_metadata(as_peer_uri=True),
        )

        return threads.deferToThread(
            click_runner.invoke,
            nucypher_cli,
            args,
            catch_exceptions=False,
            input=INSECURE_DEVELOPMENT_PASSWORD + "\n",
        )

    d = run_ursula()
    yield d
    result = d.result

    assert result.exit_code == 0, result.output
    assert "Starting services" in result.output
    assert f"{LOOPBACK_ADDRESS}:{deploy_port}" in result.output

    reserved_ports = (UrsulaConfiguration.DEFAULT_REST_PORT, UrsulaConfiguration.DEFAULT_DEVELOPMENT_REST_PORT)
    assert deploy_port not in reserved_ports

    # Check that CLI Ursula reports that it remembers the peer and saves the TLS certificate
    assert f"Saved TLS certificate for {LOOPBACK_ADDRESS}" in result.output
