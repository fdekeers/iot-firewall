from protocols.Protocol import Protocol

class arp(Protocol):

    # Class variables
    protocol_name = "arp"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "type",  # ARP message type
        "sha",   # ARP source hardware address
        "tha",   # ARP target hardware address
        "spa",   # ARP source protocol address
        "tpa"    # ARP target protocol address
    ]

    # Well-known addresses
    mac_addrs = {
        "gateway": "64:66:b3:f6:68:52",
        "default": "00:00:00:00:00:00",
    }
    ip_addrs = {
        "local": "192.168.1.1/24",
        "gateway": "192.168.1.1"
    }


    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the ARP protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        # Lambda function to explicit a self or a well-known MAC address
        func_mac = lambda mac: self.device['mac'] if mac == "self" else ( self.mac_addrs[mac] if mac in self.mac_addrs else mac )
        # Lambda function to explicit a self or a well-known IPv4 address
        func_ip = lambda ip: self.device['ipv4'] if ip == "self" else ( self.ip_addrs[ip] if ip in self.ip_addrs else ip )
        # Handle ARP message type
        rules = {"forward": "arp operation {}", "backward": "arp operation {}"}
        # Lambda function to flip the ARP type (for the backward rule)
        backward_func = lambda arp_type: "reply" if arp_type == "request" else ( "request" if arp_type == "reply" else arp_type )
        self.add_field("type", rules, direction, backward_func=backward_func)
        # Handle ARP source hardware address
        rules = {"forward": "arp saddr ether {}", "backward": "arp daddr ether {}"}
        self.add_field("sha", rules, direction, func_mac)
        # Handle ARP target hardware address
        rules = {"forward": "arp daddr ether {}", "backward": "arp saddr ether {}"}
        self.add_field("tha", rules, direction, func_mac)
        # Handle ARP source protocol address
        rules = {"forward": "arp saddr ip {}", "backward": "arp daddr ip {}"}
        self.add_field("spa", rules, direction, func_ip)
        # Handle ARP target protocol address
        rules = {"forward": "arp daddr ip {}", "backward": "arp saddr ip {}"}
        self.add_field("tpa", rules, direction, func_ip)
        return self.rules
