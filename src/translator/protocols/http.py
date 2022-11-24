from protocols.Custom import Custom

class http(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "method",
        "uri",
        "response"
    ]

    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the HTTP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Request or response
        if "response" in self.protocol_data and self.protocol_data["response"]:
            rule = {"forward": "!message.is_request"}
            if direction == "both":
                rule["backward"] = "message.is_request"
        else:
            rule = {"forward": "message.is_request"}
            if direction == "both":
                rule["backward"] = "!message.is_request"
        self.rules["nfq"].append(rule)

        # Handle HTTP method
        rule = {"forward": "message.method == {}"}
        # Lambda function to convert an HTTP method to its C representation (upper case)
        func = lambda http_method: http_method.upper()
        self.add_field("method", rule, direction, func)

        # Handle HTTP URI
        rule = {"forward": "strcmp(message.uri, \"{}\") == 0"}
        self.add_field("uri", rule, direction)
        
        return self.rules
