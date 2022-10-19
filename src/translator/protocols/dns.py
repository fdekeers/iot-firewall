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

    def parse(self, direction: str = "in") -> dict:
        """
        Parse the DHCP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle QR flag (DNS rules will always be queries)
        rules = {"forward": "message.qr == 0"}
        if direction == "both":
            rules["backward"] = "message.qr == 1"
        # Handle DNS query type
        rule = "message.questions->qtype == {}"
        rules = {"forward": rule, "backward": rule}
        self.add_field("qtype", rules, direction)
        # Handle DNS domain name
        rule = "dns_contains_domain_name(message.questions, message.header.qdcount, \"{}\")"
        rules = {"forward": rule, "backward": rule}
        self.add_field("domain-name", rules, direction)
        return self.rules
