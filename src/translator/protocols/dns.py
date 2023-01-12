from protocols.Custom import Custom

class dns(Custom):
    
    # Class variables
    layer = 7              # Protocol OSI layer
    protocol_name = "dns"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",        # DNS query type
        "domain-name"  # DNS domain name
    ]

    def parse(self, is_backward: bool = False, initiator: str = "src") -> dict:
        """
        Parse the DNS protocol.

        Args:
            is_backward (bool): Whether the protocol must be parsed for a backward rule.
                                Optional, default is `False`.
            initiator (str): Connection initiator (src or dst).
                             Optional, default is "src".
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle QR flag
        qr_rules = {}
        if "response" in self.protocol_data and self.protocol_data["response"]:
            if is_backward:
                qr_rules = {"template": "message.header.qr == {}", "match": 0}
            else:
                qr_rules = {"template": "message.header.qr == {}", "match": 1}
        else:
            if is_backward:
                qr_rules = {"template": "message.header.qr == {}", "match": 1}
            else:
                qr_rules = {"template": "message.header.qr == {}", "match": 0}
        self.rules["nfq"].append(qr_rules)

        # Handle DNS query type
        rule = "message.questions->qtype == {}"
        # Lambda function to convert an DNS query type to its C representation (upper case)
        func = lambda dns_qtype: dns_qtype.upper()
        rules = {"forward": rule, "backward": rule}
        self.add_field("qtype", rules, is_backward, func)

        # Handle DNS domain name
        rule = "dns_contains_domain_name(message.questions, message.header.qdcount, \"{}\")"
        rules = {"forward": rule, "backward": rule}
        self.add_field("domain-name", rules, is_backward)
        
        return self.rules
