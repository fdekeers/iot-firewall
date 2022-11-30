from protocols.Protocol import Protocol

class ip(Protocol):

    # Class variables
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "src",
        "dst"
    ]


    def explicit_address(self, addr: str) -> str:
        """
        Return the explicit version of an IP address alias.
        Example: "local" -> "192.168.0.0/16"

        Args:
            addr (str): IP address alias to explicit.
        Returns:
            str: Explicit IP address.
        """
        if addr == "self":
            return self.device[self.protocol_name]
        elif addr in self.addrs:
            explicit = self.addrs[addr]
            if type(explicit) == list:
                # List of correspondig explicit addresses
                return self.format_list(explicit)
            else:
                # Single corresponding explicit address
                return explicit


    def parse(self, direction: str = "out", initiator: str = "src") -> dict:
        """
        Parse the IP (v4 or v6) protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        src = "saddr {{ {} }}"
        dst = "daddr {{ {} }}"

        # Connection initiator is specified
        if initiator:
            # Template rules
            template_rules = {
                "src": {"forward": f"ct original {self.nft_prefix} {src}", "backward": f"ct original {self.nft_prefix} {dst}"},
                "dst": {"forward": f"ct original {self.nft_prefix} {dst}", "backward": f"ct original {self.nft_prefix} {src}"}
            }
            if ((initiator == "src" and (direction == "out" or direction == "both")) or
                (initiator == "dst" and direction == "in")):
                # Connection initiator is the source device
                self.add_field("src", template_rules["src"], direction, self.explicit_address)
                self.add_field("dst", template_rules["dst"], direction, self.explicit_address)
            elif ((initiator == "src" and direction == "in") or
                  (initiator == "dst" and (direction == "out" or direction == "both"))):
                # Connection initiator is the destination device
                self.add_field("src", template_rules["dst"], direction, self.explicit_address)
                self.add_field("dst", template_rules["src"], direction, self.explicit_address)

        # Connection initiator is not specified
        else:
            # Handle IPv4 source address
            rules = {"forward": f"{self.nft_prefix} {src}", "backward": f"{self.nft_prefix} {dst}"}
            self.add_field("src", rules, direction, self.explicit_address)
            # Handle IPv4 destination address
            rules = {"forward": f"{self.nft_prefix} {dst}", "backward": f"{self.nft_prefix} {src}"}
            self.add_field("dst", rules, direction, self.explicit_address)
        
        return self.rules
