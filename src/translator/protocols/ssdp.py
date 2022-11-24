from protocols.Custom import Custom

class ssdp(Custom):
    
    # Class variables
    layer = 7              # Protocol OSI layer
    protocol_name = "ssdp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "method"
    ]

    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the SSDP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # SSDP rules will always be requests
        rule = {"forward": "message.is_request"}
        if direction == "both":
            rule["backward"] = "!message.is_request"
        self.rules["nfq"].append(rule)
        # Handle SSDP method
        rule = {"forward": "message.method == {}"}
        self.add_field("method", rule, direction)
        return self.rules
