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

    def parse(self, direction: str = "out", initiator: str = "") -> dict:
        """
        Parse a layer 4 protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Add protocol match
        rule = {
            "template": "ip protocol {}",
            "match": self.protocol_name
        }
        rules = {"forward": rule, "backward": rule}
        self.rules["nft"].append(rules)

        # Connection initiator is specified
        if initiator:
            # Template rules
            template_rules = {
                "src-port": {"forward": "ct original proto-src {{ {} }}", "backward": "ct original proto-dst {{ {} }}"},
                "dst-port": {"forward": "ct original proto-dst {{ {} }}", "backward": "ct original proto-src {{ {} }}"}
            }
            if ((initiator == "src" and (direction == "out" or direction == "both")) or
                (initiator == "dst" and direction == "in")):
                # Connection initiator is the source device
                self.add_field("src-port", template_rules["src-port"], direction)
                self.add_field("dst-port", template_rules["dst-port"], direction)
            elif ((initiator == "src" and direction == "in") or
                  (initiator == "dst" and (direction == "out" or direction == "both"))):
                # Connection initiator is the destination device
                self.add_field("src-port", template_rules["dst-port"], direction)
                self.add_field("dst-port", template_rules["src-port"], direction)
        
        # Connection initiator is not specified
        else:
            # Handle source port
            rules = {"forward": self.protocol_name + " sport {{ {} }}", "backward": self.protocol_name + " dport {{ {} }}"}
            self.add_field("src-port", rules, direction)
            # Handle destination port
            rules = {"forward": self.protocol_name + " dport {{ {} }}", "backward": self.protocol_name + " sport {{ {} }}"}
            self.add_field("dst-port", rules, direction)
        
        return self.rules
