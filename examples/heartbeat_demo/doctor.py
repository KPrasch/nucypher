import base64
import json
import os
import shutil
from timeit import default_timer as timer

import maya
import msgpack
from nucypher_core import EncryptedTreasureMap, MessageKit
from nucypher_core.umbral import PublicKey

from nucypher.characters.lawful import Bob
from nucypher.crypto.keypairs import DecryptingKeypair, SigningKeypair
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.utilities.logging import GlobalLoggerSettings

######################
# Boring setup stuff #
######################

GlobalLoggerSettings.start_console_logging()

try:
    # Replace with ethereum RPC endpoint
    L1_PROVIDER = os.environ["DEMO_L1_PROVIDER_URI"]
except KeyError:
    raise RuntimeError("Missing environment variables to run demo.")


L1_NETWORK = "lynx"

# To create a Bob, we need the doctor's private keys previously generated.
from doctor_keys import get_doctor_privkeys  # noqa: E402

doctor_keys = get_doctor_privkeys()

bob_enc_keypair = DecryptingKeypair(private_key=doctor_keys["enc"])
bob_sig_keypair = SigningKeypair(private_key=doctor_keys["sig"])
enc_power = DecryptingPower(keypair=bob_enc_keypair)
sig_power = SigningPower(keypair=bob_sig_keypair)
power_ups = [enc_power, sig_power]

print("Creating the Doctor ...")

doctor = Bob(
    domain=L1_NETWORK,
    crypto_power_ups=power_ups,
    eth_provider_uri=L1_PROVIDER,
)

print("Doctor = ", doctor)

# Let's join the policy generated by Alicia. We just need some info about it.
with open("policy-metadata.json", 'r') as f:
    policy_data = json.load(f)

policy_pubkey = PublicKey.from_compressed_bytes(
    bytes.fromhex(policy_data["policy_pubkey"])
)
alices_sig_pubkey = PublicKey.from_compressed_bytes(
    bytes.fromhex(policy_data["alice_sig_pubkey"])
)
label = policy_data["label"].encode()
treasure_map = EncryptedTreasureMap.from_bytes(base64.b64decode(policy_data["treasure_map"].encode()))

# The Doctor can retrieve encrypted data which he can decrypt with his private key.
# But first we need some encrypted data!
# Let's read the file produced by the heart monitor and unpack the MessageKits,
# which are the individual ciphertexts.
data = msgpack.load(open("heart_data.msgpack", "rb"), raw=False)
message_kits = (MessageKit.from_bytes(k) for k in data['kits'])

# Now he can ask the NuCypher network to get a re-encrypted version of each MessageKit.
for message_kit in message_kits:
    start = timer()
    retrieved_plaintexts = doctor.retrieve_and_decrypt(
        [message_kit],
        alice_verifying_key=alices_sig_pubkey,
        encrypted_treasure_map=treasure_map
    )
    end = timer()

    plaintext = msgpack.loads(retrieved_plaintexts[0], raw=False)

    # Now we can get the heart rate and the associated timestamp,
    # generated by the heart rate monitor.
    heart_rate = plaintext['heart_rate']
    timestamp = maya.MayaDT(plaintext['timestamp'])

    # This code block simply pretty prints the heart rate info
    terminal_size = shutil.get_terminal_size().columns
    max_width = min(terminal_size, 120)
    columns = max_width - 12 - 27
    scale = columns / 40
    scaled_heart_rate = int(scale * (heart_rate - 60))
    retrieval_time = "Retrieval time: {:8.2f} ms".format(1000 * (end - start))
    line = ("-" * scaled_heart_rate) + "❤︎ ({} BPM)".format(heart_rate)
    line = line.ljust(max_width - 27, " ") + retrieval_time
    print(line)
