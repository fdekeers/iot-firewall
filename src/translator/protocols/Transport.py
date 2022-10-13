from protocols.Protocol import Protocol

class Transport(Protocol):
    
    # Class variables
    layer = 4              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser

    # Supported keys in YAML profile
    supported_keys = [
        "src-port",
        "dst-port"
    ]

    def parse(self) -> None:
        """
        Parse a layer 4 protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle source port
        if 'src-port' in self.parsing_data['profile_data']:
            self.parsing_data['accumulators']["nft_rule"] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']} ") + f"tcp sport {self.parsing_data['profile_data']['src-port']} "
            # Handle backwards direction
            if "nft_rule_backwards" in self.parsing_data['accumulators']:
                self.parsing_data['accumulators']["nft_rule_backwards"] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']} ") + f"tcp dport {self.parsing_data['profile_data']['src-port']} "
        # Handle destination port
        if 'dst-port' in self.parsing_data['profile_data']:
            self.parsing_data['accumulators']["nft_rule"] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']} ") + f"tcp dport {self.parsing_data['profile_data']['dst-port']} "
            # Handle backwards direction
            if "nft_rule_backwards" in self.parsing_data['accumulators']:
                self.parsing_data['accumulators']["nft_rule_backwards"] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']} ") + f"tcp sport {self.parsing_data['profile_data']['dst-port']} "
