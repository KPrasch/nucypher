import os

from nucypher_core.ferveo import FerveoPublicKey
from nucypher_core.ferveo import Keypair as FerveoKeypair

from nucypher.crypto.keypairs import RitualisticKeypair
from nucypher.crypto.powers import RitualisticPower


def test_derive_ritualistic_power(tmpdir):
    size = FerveoKeypair.secure_randomness_size()
    blob = os.urandom(size)
    keypair = RitualisticKeypair.from_secure_randomness(blob)
    power = RitualisticPower(keypair=keypair)

    assert isinstance(power, RitualisticPower)
    assert isinstance(power.keypair, RitualisticKeypair)

    public_key = power.public_key()
    assert isinstance(public_key, FerveoPublicKey)
