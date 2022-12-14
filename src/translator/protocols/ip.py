from typing import Union
import ipaddress
from protocols.Protocol import Protocol

class ip(Protocol):

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

    
    def add_addr_nfqueue(self, addr_dir: str, is_backward: bool = False) -> None:
        """
        Add a new IP address match to the nfqueue accumulator.

        Args:
            addr_dir (str): Address direction to add the rule to (src or dst)
            direction (str): Direction of the traffic (in, out, or both). Default is "out".
            initiator (str): Optional, initiator of the connection (src or dst).
        """
        other_dir = "src" if addr_dir == "dst" else "dst"
        version = int(self.protocol_name[3])
        # Template rules for a domain name
        rules_domain_name = {
            "forward": "dns_entry_contains(dns_map_get(dns_map, \"{}\"), (ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = get_" + self.protocol_name + "_" + addr_dir + "_addr(payload)}})",
            "backward": "dns_entry_contains(dns_map_get(dns_map, \"{}\"), (ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = get_" + self.protocol_name + "_" + other_dir + "_addr(payload)}})"
        }
        # Template rules for an IP address
        rules_address = {
            "forward": "compare_ip((ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = get_" + self.protocol_name + "_" + addr_dir + "_addr(payload)}}, ip_str_to_net(\"{}\", " + str(version) + "))",
            "backward": "compare_ip((ip_addr_t) {{.version = " + str(version) + ", .value." + self.protocol_name + " = get_" + self.protocol_name + "_" + other_dir + "_addr(payload)}}, ip_str_to_net(\"{}\", " + str(version) + "))"
        }

        value = self.protocol_data[addr_dir]
        rules = {}
        # If value from YAML profile is a list, produce disjunction of all elements
        if type(value) == list:
            template = "( "
            match = []
            # Value is a list
            for i in range(len(value)):
                if i != 0:
                    template += " || "
                is_ip = self.is_ip(value[i])
                template_rules = rules_address if is_ip else rules_domain_name
                func = self.explicit_address if is_ip else lambda x: x
                match.append(func(value[i]))
                if not is_backward:
                    template += template_rules["forward"]
                elif is_backward and "backward" in template_rules:
                    template += template_rules["backward"]
            rules = {"template": f"{template} )", "match": match}
        else:
            # Value is a single element
            is_ip = self.is_ip(value)
            template_rules = rules_address if is_ip else rules_domain_name
            func = self.explicit_address if is_ip else lambda x: x
            if not is_backward:
                rules = {"template": template_rules["forward"], "match": func(value)}
            elif is_backward and "backward" in template_rules:
                rules = {"template": template_rules["backward"], "match": func(value)}

        # Append rules
        if rules:
            self.rules["nfq"].append(rules)
            
    
    def add_addr(self, addr_dir: str, is_backward: bool = False, initiator: str = "") -> None:
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
                if (initiator == "src" and not is_backward) or (initiator == "dst" and is_backward):
                    # Connection initiator is the source device
                    rules = {
                        "forward": f"ct original {self.nft_prefix} {tpl_addr_matches[addr_dir]}",
                        "backward": f"ct original {self.nft_prefix} {tpl_addr_matches[other_dir]}"
                    }
                elif (initiator == "src" and is_backward) or (initiator == "dst" and not is_backward):
                    # Connection initiator is the destination device
                    rules = {
                        "forward": f"ct original {self.nft_prefix} {tpl_addr_matches[other_dir]}",
                        "backward": f"ct original {self.nft_prefix} {tpl_addr_matches[addr_dir]}"
                    }
            
            else:  # Connection initiator is not specified
                rules = {"forward": f"{self.nft_prefix} {tpl_addr_matches[addr_dir]}", "backward": f"{self.nft_prefix} {tpl_addr_matches[other_dir]}"}
            
            self.add_field(addr_dir, rules, is_backward, self.explicit_address)

        else:  # Source address is potentially a domain name
            self.add_addr_nfqueue(addr_dir, is_backward)


    def parse(self, is_backward: bool = False, initiator: str = "") -> dict:
        """
        Parse the IP (v4 or v6) protocol.

        Args:
            is_backward (bool): Whether the protocol must be parsed for a backward rule.
                                Optional, default is `False`.
            initiator (str): Connection initiator (src or dst).
                             Optional, default is "src".
        Returns:
            dict: Dictionary containing the (forward and backward) nftables and nfqueue rules for this policy.
        """
        if "src" in self.protocol_data:
            # Source address is specified
            self.add_addr("src", is_backward, initiator)
        if "dst" in self.protocol_data:
            # Destination address is specified
            self.add_addr("dst", is_backward, initiator)
        return self.rules
