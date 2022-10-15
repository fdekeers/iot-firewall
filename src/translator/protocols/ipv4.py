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
    def parse(self) -> None:
        """
        Parse the IPv4 protocol.
        Updates the accumulator values for the nftables and custom C rules.
        """
        # Lambda function to explicit a self or a well-known IP address
        func = lambda ip: self.metadata['device']['ip'] if ip == "self" else ( self.addrs[ip] if ip in self.addrs else ip )
        # Handle IPv4 source address
        rules = {"forward": "ip saddr {}", "backward": "ip daddr {}"}
        self.add_field("src", rules, func)
        # Handle IPv4 destination address
        rules = {"forward": "ip daddr {}", "backward": "ip saddr {}"}
        self.add_field("dst", rules, func)
