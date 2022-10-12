from typing import Tuple
from protocols.Protocol import Protocol

class Transport(Protocol):
    
    # Class variables
    layer = 4              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser

    # Supported keys in YAML profile
    supported_keys = [
        "src-port",
        "dst-port"
    ]

    def parse(self, data: dict, states: dict, accumulators: dict) -> None:
        """
        Parse a layer 4 protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle source port
        if 'src-port' in data:
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"tcp sport {data['src-port']} "
            # Handle backwards direction
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"tcp dport {data['src-port']} "
        # Handle destination port
        if 'dst-port' in data:
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"tcp dport {data['dst-port']} "
            # Handle backwards direction
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"tcp sport {data['dst-port']} "
