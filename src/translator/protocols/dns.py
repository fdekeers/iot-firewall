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

    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the DNS protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle QR flag
        if "response" in self.protocol_data and self.protocol_data["response"]:
            rules = {"forward": {"template": "message.header.qr == {}", "match": 1}}
            if direction == "both":
                rules["backward"] = {"template": "message.header.qr == {}", "match": 0}
        else:
            rules = {"forward": {"template": "message.header.qr == {}", "match": 0}}
            if direction == "both":
                rules["backward"] = {"template": "message.header.qr == {}", "match": 1}
        self.rules["nfq"].append(rules)

        # Handle DNS query type
        rule = "message.questions->qtype == {}"
        # Lambda function to convert an DNS query type to its C representation (upper case)
        func = lambda ssdp_method: ssdp_method.upper()
        rules = {"forward": rule, "backward": rule}
        self.add_field("qtype", rules, direction, func)

        # Handle DNS domain name
        rule = "dns_contains_domain_name(message.questions, message.header.qdcount, \"{}\")"
        rules = {"forward": rule, "backward": rule}
        self.add_field("domain-name", rules, direction)
        
        return self.rules
