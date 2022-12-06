from protocols.Custom import Custom

class ssdp(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "ssdp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "method",
        "response"
    ]

    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the SSDP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
       # Request or response
        if "response" in self.protocol_data and self.protocol_data["response"]:
            rule = {"forward": {"template": "{}message.is_request", "match": "!"}}
            if direction == "both":
                rule["backward"] = {"template": "{}message.is_request", "match": ""}
        else:
            rule = {"forward": {"template": "{}message.is_request", "match": ""}}
            if direction == "both":
                rule["backward"] = {"template": "{}message.is_request", "match": "!"}
        self.rules["nfq"].append(rule)

        # Handle SSDP method
        rule = {"forward": "message.method == {}"}
        # Lambda function to convert an SSDP method to its C representation (upper case and separated by underscores)
        func = lambda ssdp_method: ssdp_method.upper().replace("-", "_")
        self.add_field("method", rule, direction, func)
        
        return self.rules
