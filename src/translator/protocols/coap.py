from protocols.Custom import Custom

class coap(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "coap"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",
        "method",
        "uri"
    ]

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the CoAP protocol.

        Args:
            is_backward (bool): Whether the protocol must be parsed for a backward rule.
                                Optional, default is `False`.
            initiator (str): Connection initiator (src or dst).
                             Optional, default is "src".
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Lambda function to convert a CoAP type or method to its C representation (upper case and separated by underscores)
        func = lambda field: field.upper().replace("-", "_")

        # Handle CoAP message type
        rule = {"forward": "message.type == {}"}
        self.add_field("type", rule, is_backward, func)

        # Handle CoAP method
        rule = {"forward": "message.method == {}"}
        self.add_field("method", rule, is_backward, func)

        # Handle CoAP URI
        rule = {"forward": "strcmp(message.uri, \"{}\") == 0"}
        self.add_field("uri", rule, is_backward)
        
        return self.rules
