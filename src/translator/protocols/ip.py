from typing import Union
import ipaddress
from protocols.Protocol import Protocol
from protocols.Custom import Custom

class ip(Custom, Protocol):

    # Class variables
    layer = 3              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "src",
        "dst"
    ]


    def is_ip(self, addr: Union[str, list]) -> bool:
        """
        Check whether a (list of) string is a well-known IP alias or an explicit IP address.
        Args:
            addr (Union[str, list]): (list of) string to check.
        Returns:
            bool: True if the (list of) string is an IP address, False otherwise.
        """
        if type(addr) == list:
            # List of addresses
            return all([self.is_ip(a) for a in addr])
        
        # Single address
        if addr == "self" or addr in self.addrs:
            # Address is a well-known alias
            return True
        # Address is not a well-known alias
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            # Address is not an explicit address
            return False


    def explicit_address(self, addr: str) -> str:
        """
        Return the explicit version of an IP address alias.
        Example: "local" -> "192.168.0.0/16"

        Args:
            addr (str): IP address alias to explicit.
        Returns:
            str: Explicit IP address.
        Exception:
            ValueError: If the address is not a well-known alias or an explicit address.
        """
        if not self.is_ip(addr):
            # Address is invalid
            raise ValueError(f"Unknown address: {addr}")
        
        # Address is valid
        if addr == "self":
            # Address is "self"
            return self.device[self.protocol_name]
        elif addr in self.addrs:
            # Address is a well-known address alias
            explicit = self.addrs[addr]
            if type(explicit) == list:
                # List of correspondig explicit addresses
                return self.format_list(explicit)
            else:
                # Single corresponding explicit address
                return explicit
        else:
            # Address is an explicit address
            return addr
            
    
    def add_addr(self, addr_dir: str, direction: str = "out", initiator: str = "") -> None:
        """
        Add a new IP address match to the accumulator, in two possible ways:
            - If the address is a well-known alias or an explicit IP address, add an nftables match.
            - If the address is a domain name, add an nfqueue match.

        Args:
            addr_dir (str): Address direction to add the rule to (src or dst)
            direction (str): Direction of the traffic (in, out, or both). Default is "out".
            initiator (str): Optional, initiator of the connection (src or dst).
        """
        other_dir = "src" if addr_dir == "dst" else "dst"
        addr = self.protocol_data[addr_dir]

        if self.is_ip(addr):  # Source address is a well-known alias or an explicit IP address
            tpl_addr_matches = {
                "src": "saddr {{ {} }}",
                "dst": "daddr {{ {} }}"
            }
            if initiator:  # Connection initiator is specified
                if ((initiator == "src" and (direction == "out" or direction == "both")) or
                (initiator == "dst" and direction == "in")):
                    # Connection initiator is the source device
                    rules = {
                        "forward": f"ct original {self.nft_prefix} {tpl_addr_matches[addr_dir]}",
                        "backward": f"ct original {self.nft_prefix} {tpl_addr_matches[other_dir]}"
                    }
                    Protocol.add_field(self, addr_dir, rules, direction, self.explicit_address)
                elif ((initiator == "src" and direction == "in") or
                  (initiator == "dst" and (direction == "out" or direction == "both"))):
                    # Connection initiator is the destination device
                    rules = {
                        "forward": f"ct original {self.nft_prefix} {tpl_addr_matches[other_dir]}",
                        "backward": f"ct original {self.nft_prefix} {tpl_addr_matches[addr_dir]}"
                    }
                    Protocol.add_field(self, addr_dir, rules, direction, self.explicit_address)
            
            else:  # Connection initiator is not specified
                rules = {"forward": f"{self.nft_prefix} {tpl_addr_matches[addr_dir]}", "backward": f"{self.nft_prefix} {tpl_addr_matches[other_dir]}"}
                Protocol.add_field(self, "src", rules, direction, self.explicit_address)

        else:  # Source address is potentially a domain name
            rules = {
                "forward": f"dns_entry_contains(dns_map_get(dns_map, \"{{}}\"), get_{self.protocol_name}_{addr_dir}_addr(payload))",
                "backward": f"dns_entry_contains(dns_map_get(dns_map, \"{{}}\"), get_{self.protocol_name}_{other_dir}_addr(payload))"
            }
            Custom.add_field(self, addr_dir, rules, direction)


    def parse(self, direction: str = "out", initiator: str = "") -> dict:
        """
        Parse the IP (v4 or v6) protocol.

        Args:
            direction (str): Direction of the traffic (in, out, or both).
            initiator (str): Optional, initiator of the connection (src or dst).
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        if "src" in self.protocol_data:
            # Source address is specified
            self.add_addr("src", direction, initiator)
        if "dst" in self.protocol_data:
            # Destination address is specified
            self.add_addr("dst", direction, initiator)
        return self.rules
