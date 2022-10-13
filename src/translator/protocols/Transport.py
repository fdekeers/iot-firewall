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

    def parse(self) -> None:
        """
        Parse a layer 4 protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle source port
        rules = {"forward": f"{self.protocol_name} sport {{}}", "backward": f"{self.protocol_name} dport {{}}"}
        self.add_field("src-port", rules)
        # Handle destination port
        rules = {"forward": f"{self.protocol_name} dport {{}}", "backward": f"{self.protocol_name} sport {{}}"}
        self.add_field("dst-port", rules)
