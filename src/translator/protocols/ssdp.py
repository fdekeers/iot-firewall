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

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the SSDP protocol.

        Args:
            is_backward (bool): Whether the protocol must be parsed for a backward rule.
                                Optional, default is `False`.
            initiator (str): Connection initiator (src or dst).
                             Optional, default is "src".
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Request or response
        ssdp_type_rule = {}
        if "response" in self.protocol_data and self.protocol_data["response"]:
            if is_backward:
                ssdp_type_rule = {"template": "{}message.is_request", "match": ""}
            else:
                ssdp_type_rule = {"template": "{}message.is_request", "match": "!"}
        else:
            if is_backward:
                ssdp_type_rule = {"template": "{}message.is_request", "match": "!"}
            else:
                ssdp_type_rule = {"template": "{}message.is_request", "match": ""}
        self.rules["nfq"].append(ssdp_type_rule)

        # Handle SSDP method
        rule = {"forward": "message.method == {}"}
        # Lambda function to convert an SSDP method to its C representation (upper case and separated by underscores)
        func = lambda ssdp_method: ssdp_method.upper().replace("-", "_")
        self.add_field("method", rule, is_backward, func)
        
        return self.rules
