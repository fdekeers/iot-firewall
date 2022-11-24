from protocols.Custom import Custom

class dhcp(Custom):
    
    # Class variables
    layer = 7               # Protocol OSI layer
    protocol_name = "dhcp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",
        "client-mac"
    ]

    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the DHCP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle DHCP message type
        rules = {"forward": "message.options.message_type == {}"}
        # Lambda function to convert an IGMP type to its C representation (upper case)
        func = lambda dhcp_type: dhcp_type.upper()
        self.add_field("type", rules, direction, func)
        # Handle DHCP client MAC address
        rules = {"forward": "strcmp(mac_hex_to_str(message.chaddr), \"{}\") == 0"}
        # Lambda function to explicit a self MAC address
        func = lambda mac: self.device['mac'] if mac == "self" else mac
        self.add_field("client-mac", rules, direction, func)
        return self.rules
