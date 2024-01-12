import pytest

from nucypher.blockchain.eth import domains
from nucypher.characters.chaotic import (
    NiceGuyEddie,
    ThisBobAlwaysDecrypts,
    ThisBobAlwaysFails,
)
from nucypher.characters.lawful import Ursula
from nucypher.policy.conditions.lingo import ConditionLingo, ConditionType
from tests.constants import (
    MOCK_ETH_PROVIDER_URI,
    MOCK_REGISTRY_FILEPATH,
    TESTERCHAIN_CHAIN_ID,
)
from tests.utils.blockchain import TestAccount


def _attempt_decryption(BobClass, plaintext, testerchain, peers):
    trinket = 80  # Doesn't matter.

    wallet = TestAccount.random()
    enrico = NiceGuyEddie(encrypting_key=trinket, wallet=wallet)
    bob = BobClass(
        registry=MOCK_REGISTRY_FILEPATH,
        domain=domains.LYNX,
        eth_endpoint=MOCK_ETH_PROVIDER_URI,
        seed_nodes=peers,
        start_peering_now=False,
        lonely=True,
    )

    definitely_false_condition = {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.TIME.value,
            "chain": TESTERCHAIN_CHAIN_ID,
            "method": "blocktime",
            "returnValueTest": {"comparator": "<", "value": 0},
        },
    }

    threshold_message_kit = enrico.encrypt_for_dkg(
        plaintext=plaintext,
        conditions=definitely_false_condition,
    )

    decrypted_cleartext = bob.threshold_decrypt(
        threshold_message_kit=threshold_message_kit,
    )

    return decrypted_cleartext


def test_user_controls_success(testerchain, ursulas):
    plaintext = b"ever thus to deadbeats"
    result = _attempt_decryption(ThisBobAlwaysDecrypts, plaintext, testerchain, ursulas)
    assert bytes(result) == bytes(plaintext)


def test_user_controls_failure(testerchain, ursulas):
    plaintext = b"ever thus to deadbeats"
    with pytest.raises(Ursula.NotEnoughUrsulas):
        _ = _attempt_decryption(ThisBobAlwaysFails, plaintext, testerchain, ursulas)
