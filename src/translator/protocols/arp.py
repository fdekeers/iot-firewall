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


    def parse(self) -> dict:
        """
        Parse the ARP protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle ARP message type
        rules = {"forward": "arp operation {}", "backward": "arp operation {}"}
        # Lambda function to flip the ARP type (for the backward rule)
        backward_func = lambda arp_type: "reply" if arp_type == "request" else ( "request" if arp_type == "reply" else arp_type )
        self.add_field("type", rules, backward_func=backward_func)
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
