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
        if 'src' in self.parsing_data['profile_data']:
            ip = self.parsing_data['profile_data']['src'] if self.parsing_data['profile_data']['src'] != "self" else self.metadata['device']['ip']
            self.parsing_data['accumulators']["nft_rule"] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']} ") + f"ip saddr {ip} "
            # Handle backwards direction
            if "nft_rule_backwards" in self.parsing_data['accumulators']:
                self.parsing_data['accumulators']["nft_rule_backwards"] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']} ") + f"ip daddr {ip} "
        # Handle IPv4 destination address
        if 'dst' in self.parsing_data['profile_data']:
            ip = self.parsing_data['profile_data']['dst'] if self.parsing_data['profile_data']['dst'] != "self" else self.metadata['device']['ip']
            self.parsing_data['accumulators']["nft_rule"] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']} ") + f"ip daddr {ip} "
            # Handle backwards direction
            if "nft_rule_backwards" in self.parsing_data['accumulators']:
                self.parsing_data['accumulators']["nft_rule_backwards"] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']} ") + f"ip saddr {ip} "
