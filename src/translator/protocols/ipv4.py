from protocols.Protocol import Protocol

class ipv4(Protocol):

    # Class variables
    protocol_name = "ipv4"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "src",
        "dst"
    ]

    def parse(self) -> None:
        """
        Parse the IPv4 protocol.
        Updates the accumulator values for the nftables and custom C rules.
        """
        # Handle IPv4 source address
        if self.parsing_data['profile_data'].get("src", None) == "self":
            self.parsing_data['profile_data']["src"] = self.metadata['device']['ip']
        rules = {"forward": "ip saddr {}", "backward": "ip daddr {}"}
        self.add_field("src", rules)
        # Handle IPv4 destination address
        if self.parsing_data['profile_data'].get("dst", None) == "self":
            self.parsing_data['profile_data']['dst'] = self.metadata['device']['ip']
        rules = {"forward": "ip daddr {}", "backward": "ip saddr {}"}
        self.add_field("dst", rules)
