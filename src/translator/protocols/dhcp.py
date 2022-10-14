from protocols.Custom import Custom

class dhcp(Custom):
    
    # Class variables
    protocol_name = "dhcp"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",
        "client-mac"
    ]

    def handle_app_fields(self) -> None:
        """
        Handle the different protocol fields.
        """
        # Handle DHCP message type
        rules = {"forward": "message.options.message_type == {}"}
        # Lambda function to convert an IGMP type to its C representation (upper case)
        func = lambda dhcp_type: dhcp_type.upper()
        self.add_field("type", rules, func)
        # Handle DHCP client MAC address
        rules = {"forward": "strcmp(mac_hex_to_str(message.chaddr), \"{}\") == 0"}
        # Lambda function to explicit a self MAC address
        func = lambda mac: self.metadata['device']['mac'] if mac == "self" else mac
        self.add_field("client-mac", rules, func)
