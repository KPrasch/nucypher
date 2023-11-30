from nucypher.characters.chaotic import NiceGuyEddie as _Enrico
from nucypher.characters.chaotic import ThisBobAlwaysDecrypts
from nucypher.policy.conditions.lingo import ConditionLingo

plaintext = b"paz al amanecer"
THIS_IS_NOT_A_TRINKET = 55  # sometimes called "public key"

enrico = _Enrico(encrypting_key=THIS_IS_NOT_A_TRINKET)
bob = ThisBobAlwaysDecrypts(domain="lynx", eth_provider_uri="Nowhere")

ANYTHING_CAN_BE_PASSED_AS_RITUAL_ID = 55

before_the_beginning_of_time = {
    "version": ConditionLingo.VERSION,
    "condition": {
        "conditionType": "time",
        "chain": 1,
        "method": "blocktime",
        "returnValueTest": {"comparator": "<", "value": 0},
    },
}

dkg_message_kit = enrico.encrypt_for_dkg(
    plaintext=plaintext,
    conditions=before_the_beginning_of_time,
)

cleartext_from_ciphertext = bob.threshold_decrypt(
    ritual_id=ANYTHING_CAN_BE_PASSED_AS_RITUAL_ID,
    dkg_message_kit=dkg_message_kit,
)

decoded_cleartext_from_ciphertext = bytes(cleartext_from_ciphertext)

assert decoded_cleartext_from_ciphertext == plaintext
print(f"Decrypted cleartext: {decoded_cleartext_from_ciphertext}")
