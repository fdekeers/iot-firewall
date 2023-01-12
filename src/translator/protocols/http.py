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

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the HTTP protocol.

        Args:
            is_backward (bool): Whether the protocol must be parsed for a backward rule.
                                Optional, default is `False`.
            initiator (str): Connection initiator (src or dst).
                             Optional, default is "src".
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Request or response
        http_type_rule = {}
        if "response" in self.protocol_data and self.protocol_data["response"]:
            if is_backward:
                http_type_rule = {"template": "{}message.is_request", "match": ""}
            else:
                http_type_rule = {"template": "{}message.is_request", "match": "!"}
        else:
            if is_backward:
                http_type_rule = {"template": "{}message.is_request", "match": "!"}
            else:
                http_type_rule = {"template": "{}message.is_request", "match": ""}
        self.rules["nfq"].append(http_type_rule)

        # Handle HTTP method
        rule = {"forward": "message.method == {}"}
        # Lambda function to convert an HTTP method to its C representation (upper case)
        func = lambda http_method: http_method.upper()
        self.add_field("method", rule, is_backward, func)

        # Handle HTTP URI
        rule = {"forward": "strcmp(message.uri, \"{}\") == 0"}
        self.add_field("uri", rule, is_backward)
        
        return self.rules
