from protocols.Custom import Custom

class igmp(Custom):
    
    # Class variables
    layer = 3               # Protocol OSI layer
    protocol_name = "igmp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        'type',
        'group'
    ]

    # Well-known groups
    groups = {
        "mdns": "224.0.0.251"
    }


    def parse(self, direction: str = "in") -> dict:
        """
        Parse the IGMP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Handle IGMP message type
        rules = {"forward": "message.type == {}"}
        # Lambda function to convert an IGMP type to its C representation (upper case and separated by underscores)
        func = lambda igmp_type: igmp_type.upper().replace(" ", "_")
        self.add_field("type", rules, direction, func)
        # Handle IGMP group
        rules = {"forward": "strcmp(ip_hex_to_str(message.group_address), \"{}\") == 0"}
        # Lambda function to explicit the address of a well-known group
        func = lambda igmp_group: self.groups[igmp_group] if igmp_group in self.groups else igmp_group
        self.add_field("group", rules, direction, func)
        return self.rules