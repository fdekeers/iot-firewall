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

    # Well-known addresses
    addrs = {
        "local": "192.168.1.1/24",
        "gateway": "192.168.1.1",
        "broadcast": "192.168.1.255",
        "mdns": "224.0.0.251"
    }


    # TODO: translate domain names
    def parse(self, direction: str = "in") -> dict:
        """
        Parse the IPv4 protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Lambda function to explicit a self or a well-known IP address
        func = lambda ip: self.device['ip'] if ip == "self" else ( self.addrs[ip] if ip in self.addrs else ip )
        # Handle IPv4 source address
        rules = {"forward": "ip saddr {}", "backward": "ip daddr {}"}
        self.add_field("src", rules, direction, func)
        # Handle IPv4 destination address
        rules = {"forward": "ip daddr {}", "backward": "ip saddr {}"}
        self.add_field("dst", rules, direction, func)
        return self.rules
