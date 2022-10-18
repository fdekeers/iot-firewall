from protocols.Custom import Custom

class http(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "request-type",
        "uri"
    ]

    def parse(self, direction: str = "in") -> dict:
        """
        Parse the DHCP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # HTTP rules will always be requests
        rule = {"forward": "message.is_request"}
        if direction == "both":
            rule["backward"] = "!message.is_request"
        self.rules["nfq"].append(rule)
        # Handle HTTP method
        rule = {"forward": "message.method == {}"}
        self.add_field("method", rule, direction)
        # Handle HTTP URI
        rule = {"forward": "strcmp(message.uri, \"{}\") == 0"}
        self.add_field("uri", rule, direction)
        return self.rules
