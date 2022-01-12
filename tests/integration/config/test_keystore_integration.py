"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""


import tempfile
from unittest.mock import ANY

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Flask

from nucypher.characters.lawful import Alice, Bob, Ursula
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.keystore import Keystore
from nucypher.crypto.powers import DecryptingPower, DelegatingPower, TLSHostingPower
from nucypher.crypto.umbral_adapter import SecretKey, Signer
from nucypher.datastore.datastore import Datastore
from nucypher.network.server import ProxyRESTServer
from nucypher.utilities.networking import LOOPBACK_ADDRESS
from tests.constants import INSECURE_DEVELOPMENT_PASSWORD
from tests.utils.matchers import IsType


def test_generate_alice_keystore(temp_dir_path):

    keystore = Keystore.generate(
        password=INSECURE_DEVELOPMENT_PASSWORD,
        keystore_dir=temp_dir_path
    )

    with pytest.raises(Keystore.Locked):
        _dec_keypair = keystore.derive_crypto_power(DecryptingPower).keypair

    keystore.unlock(password=INSECURE_DEVELOPMENT_PASSWORD)
    assert keystore.derive_crypto_power(DecryptingPower).keypair

    label = b'test'

    delegating_power = keystore.derive_crypto_power(DelegatingPower)
    delegating_pubkey = delegating_power.get_pubkey_from_label(label)

    bob_pubkey = SecretKey.random().public_key()
    signer = Signer(SecretKey.random())
    delegating_pubkey_again, _kfrags = delegating_power.generate_kfrags(
        bob_pubkey, signer, label, threshold=2, shares=3
    )

    assert delegating_pubkey == delegating_pubkey_again

    another_delegating_power = keystore.derive_crypto_power(DelegatingPower)
    another_delegating_pubkey = another_delegating_power.get_pubkey_from_label(label)

    assert delegating_pubkey == another_delegating_pubkey


def test_characters_use_keystore(temp_dir_path):
    keystore = Keystore.generate(
        password=INSECURE_DEVELOPMENT_PASSWORD,
        keystore_dir=temp_dir_path
    )
    keystore.unlock(password=INSECURE_DEVELOPMENT_PASSWORD)
    alice = Alice(federated_only=True, start_learning_now=False, keystore=keystore)
    Bob(federated_only=True, start_learning_now=False, keystore=keystore)
    Ursula(federated_only=True,
           start_learning_now=False,
           keystore=keystore,
           rest_host=LOOPBACK_ADDRESS,
           rest_port=12345,
           db_filepath=tempfile.mkdtemp(),
           domain=TEMPORARY_DOMAIN)
    alice.disenchant()  # To stop Alice's publication threadpool.  TODO: Maybe only start it at first enactment?


@pytest.mark.skip('Do we really though?')
def test_tls_hosting_certificate_remains_the_same(temp_dir_path, mocker):
    keystore = Keystore.generate(
        password=INSECURE_DEVELOPMENT_PASSWORD,
        keystore_dir=temp_dir_path
    )
    keystore.unlock(password=INSECURE_DEVELOPMENT_PASSWORD)

    rest_port = 12345
    db_filepath = tempfile.mkdtemp()

    ursula = Ursula(federated_only=True,
                    start_learning_now=False,
                    keystore=keystore,
                    rest_host=LOOPBACK_ADDRESS,
                    rest_port=rest_port,
                    db_filepath=db_filepath,
                    domain=TEMPORARY_DOMAIN)

    assert ursula.keystore is keystore
    assert ursula.certificate == ursula._crypto_power.power_ups(TLSHostingPower).keypair.certificate

    original_certificate_bytes = ursula.certificate.public_bytes(encoding=Encoding.PEM)
    ursula.disenchant()
    del ursula

    spy_rest_server_init = mocker.spy(ProxyRESTServer, '__init__')
    recreated_ursula = Ursula(federated_only=True,
                              start_learning_now=False,
                              keystore=keystore,
                              rest_host=LOOPBACK_ADDRESS,
                              rest_port=rest_port,
                              db_filepath=db_filepath,
                              domain=TEMPORARY_DOMAIN)

    assert recreated_ursula.keystore is keystore
    assert recreated_ursula.certificate.public_bytes(encoding=Encoding.PEM) == original_certificate_bytes
    tls_hosting_power = recreated_ursula._crypto_power.power_ups(TLSHostingPower)
    spy_rest_server_init.assert_called_once_with(ANY,  # self
                                                 rest_host=LOOPBACK_ADDRESS,
                                                 rest_port=rest_port,
                                                 rest_app=IsType(Flask),
                                                 datastore=IsType(Datastore),
                                                 hosting_power=tls_hosting_power)
    recreated_ursula.disenchant()
