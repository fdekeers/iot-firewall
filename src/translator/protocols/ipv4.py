from typing import Tuple
from protocols.Protocol import Protocol

class ipv4(Protocol):

    # Class variables
    protocol_name = "ipv4"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "src",
        "dst"
    ]

    def parse(self, data: dict, states: dict, accumulators: dict) -> None:
        """
        Parse the IPv4 protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle IPv4 source address
        if 'src' in data:
            ip = data['src'] if data['src'] != "self" else self.device['ip']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"ip saddr {ip} "
            # Handle backwards direction
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"ip daddr {ip} "
        # Handle IPv4 destination address
        if 'dst' in data:
            ip = data['dst'] if data['dst'] != "self" else self.device['ip']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"ip daddr {ip} "
            # Handle backwards direction
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"ip saddr {ip} "
