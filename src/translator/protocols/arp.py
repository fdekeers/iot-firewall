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

    def parse(self) -> dict:
        """
        Parse the ARP protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle ARP message type
        if 'type' in self.parsing_data['profile_data']:
            arp_type = self.parsing_data['profile_data']['type']
            self.parsing_data['accumulators']["nft_rule"] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']} ") + f"arp operation {arp_type} "
            if "nft_rule_backwards" in self.parsing_data['accumulators']:
                self.parsing_data['accumulators']["nft_rule_backwards"] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']} ") + f"arp operation {self.flip_type(arp_type)} "
        # Handle ARP source hardware address
        rules = {"forward": "arp saddr ether {}", "backward": "arp daddr ether {}"}
        self.add_field("sha", rules)
        # Handle ARP target hardware address
        rules = {"forward": "arp daddr ether {}", "backward": "arp saddr ether {}"}
        self.add_field("tha", rules)
        # Handle ARP source protocol address
        rules = {"forward": "arp saddr ip {}", "backward": "arp daddr ip {}"}
        self.add_field("spa", rules)
        # Handle ARP target protocol address
        rules = {"forward": "arp daddr ip {}", "backward": "arp saddr ip {}"}
        self.add_field("tpa", rules)
