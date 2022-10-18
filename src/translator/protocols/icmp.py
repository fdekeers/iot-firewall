from protocols.Protocol import Protocol

class icmp(Protocol):

    # Class variables
    protocol_name = "icmp"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "type"  # ICMP message type
    ]


    def parse(self, direction: str = "in") -> dict:
        """
        Parse the ICMP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle ICMP message type
        rules = {"forward": "icmp type {}", "backward": "icmp type {}"}
        # Lambda function to flip the ICMP type (for the backward rule)
        backward_func = lambda icmp_type: icmp_type.replace("request", "reply") if "request" in icmp_type else ( icmp_type.replace("reply", "request") if "reply" in icmp_type else icmp_type )
        self.add_field("type", rules, direction, backward_func=backward_func)
        return self.rules
