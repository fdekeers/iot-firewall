from typing import Tuple
from webbrowser import get
from protocols.Protocol import Protocol

class arp(Protocol):

    # Class variables
    protocol_name = "arp"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "type",  # ARP message type
        "sha",   # ARP source hardware address
        "tha",   # ARP target hardware address
        "spa",   # ARP source protocol address
        "tpa"    # ARP target protocol address
    ]

    @staticmethod
    def flip_type(arp_type: str) -> str:
        """
        Flip the given ARP type.

        Args:
            arp_type (str): ARP type.

        Returns:
            str: 'reply' if the given type was 'request',
                 'request' if the given type was 'reply'.
        """
        if arp_type == "request":
            return "reply"
        elif arp_type == "reply":
            return "request"

    def parse(self, data: dict, states: dict, accumulators: dict) -> dict:
        """
        Parse the ARP protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle ARP message type
        if 'type' in data:
            arp_type = data['type']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"arp operation {arp_type} "
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"arp operation {self.flip_type(arp_type)} "
        # Handle ARP source hardware address
        if 'sha' in data:
            sha = data['sha']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"arp saddr ether {sha} "
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"arp daddr ether {sha} "
        # Handle ARP target hardware address
        if 'tha' in data:
            tha = data['tha']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"arp daddr ether {tha} "
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"arp saddr ether {tha} "
        # Handle ARP source protocol address
        if 'spa' in data:
            spa = data['spa']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"arp saddr ip {spa} "
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"arp daddr ip {spa} "
        # Handle ARP target protocol address
        if 'tpa' in data:
            tpa = data['tpa']
            accumulators["nft_rule"] = accumulators.get("nft_rule", f"nft add rule {self.nft_table_chain} ") + f"arp daddr ip {tpa} "
            if "nft_rule_backwards" in accumulators:
                accumulators["nft_rule_backwards"] = accumulators.get("nft_rule_backwards", f"nft add rule {self.nft_table_chain} ") + f"arp saddr ip {tpa} "
