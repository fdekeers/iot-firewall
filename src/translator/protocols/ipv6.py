from protocols.Protocol import Protocol

class ipv6(Protocol):

    # Class variables
    protocol_name = "ipv6"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "src",
        "dst"
    ]

    # Well-known addresses
    addrs = {
        "local": "fe80::/10",
        "gateway": "fddd:ed18:f05b::1",
        "mdns": "ff02::fb"
    }


    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the IPv6 protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Lambda function to explicit a self or a well-known IP address
        func = lambda ip: self.device['ipv6'] if ip == "self" else ( self.addrs[ip] if ip in self.addrs else ip )

        # Connection initiator is specified
        if initiator:
            # Template rules
            template_rules = {
                "src": {"forward": f"ct original saddr src={{}}", "backward": f"ct original daddr dst={{}}"},
                "dst": {"forward": f"ct original daddr dst={{}}", "backward": f"ct original saddr src={{}}"}
            }
            if ((initiator == "src" and (direction == "out" or direction == "both")) or
                (initiator == "dst" and direction == "in")):
                # Connection initiator is the source device
                self.add_field("src", template_rules["src"], direction, func)
                self.add_field("dst", template_rules["dst"], direction, func)
            elif ((initiator == "src" and direction == "in") or
                  (initiator == "dst" and (direction == "out" or direction == "both"))):
                # Connection initiator is the destination device
                self.add_field("src", template_rules["dst"], direction, func)
                self.add_field("dst", template_rules["src"], direction, func)

        # Connection initiator is not specified
        else:
            # Handle IPv4 source address
            rules = {"forward": "ip saddr {}", "backward": "ip daddr {}"}
            self.add_field("src", rules, direction, func)
            # Handle IPv4 destination address
            rules = {"forward": "ip daddr {}", "backward": "ip saddr {}"}
            self.add_field("dst", rules, direction, func)
        
        return self.rules
