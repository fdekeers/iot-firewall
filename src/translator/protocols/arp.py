from typing import Tuple
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

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> Tuple[str, str, str]:
        """
        Parse the ARP protocol.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction.

        Returns:
            Tuple[str, str, str]: updated values of the arguments nft_rule, callback_funcs, nft_rule_backwards
        """
        # Handle ARP message type
        if 'type' in data:
            arp_type = data['type']
            nft_rule += f"arp operation {arp_type} "
            if nft_rule_backwards:
                nft_rule_backwards += f"arp operation {self.flip_type(arp_type)} "
        # Handle ARP source hardware address
        if 'sha' in data:
            sha = data['sha']
            nft_rule += f"arp saddr ether {sha} "
            if nft_rule_backwards:
                nft_rule_backwards += f"arp daddr ether {sha} "
        # Handle ARP target hardware address
        if 'tha' in data:
            tha = data['tha']
            nft_rule += f"arp daddr ether {tha} "
            if nft_rule_backwards:
                nft_rule_backwards += f"arp saddr ether {tha} "
        # Handle ARP source protocol address
        if 'spa' in data:
            spa = data['spa']
            nft_rule += f"arp saddr ip {spa} "
            if nft_rule_backwards:
                nft_rule_backwards += f"arp daddr ip {spa} "
        # Handle ARP target protocol address
        if 'tpa' in data:
            tpa = data['tpa']
            nft_rule += f"arp daddr ip {tpa} "
            if nft_rule_backwards:
                nft_rule_backwards += f"arp saddr ip {tpa} "

        return nft_rule, callback_funcs, nft_rule_backwards
