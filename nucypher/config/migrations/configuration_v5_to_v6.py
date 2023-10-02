from typing import Dict

from nucypher.blockchain.eth.networks import NetworksInventory
from nucypher.config.migrations.common import perform_migration


def __migration(config: Dict) -> Dict:
    taco_network = NetworksInventory.get_network(config["domain"])
    eth_provider = config["eth_provider_uri"]
    eth_chain_id = taco_network.eth_network.id
    polygon_provider = config["payment_provider"]
    polygon_chain_id = taco_network.poly_network.id
    if "condition_provider_uris" in config:
        return config
    config["condition_provider_uris"] = {
        eth_chain_id: [eth_provider],
        polygon_chain_id: [polygon_provider],
    }
    return config


def configuration_v5_to_v6(filepath) -> None:
    perform_migration(
        old_version=5, new_version=6, migration=__migration, filepath=filepath
    )
