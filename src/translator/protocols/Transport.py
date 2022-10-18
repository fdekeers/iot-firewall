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

    def parse(self, direction: str = "in") -> dict:
        """
        Parse a layer 4 protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle source port
        rules = {"forward": f"{self.protocol_name} sport {{}}", "backward": f"{self.protocol_name} dport {{}}"}
        self.add_field("src-port", rules, direction)
        # Handle destination port
        rules = {"forward": f"{self.protocol_name} dport {{}}", "backward": f"{self.protocol_name} sport {{}}"}
        self.add_field("dst-port", rules, direction)
        return self.rules
