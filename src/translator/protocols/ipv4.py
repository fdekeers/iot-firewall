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

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> str:
        """
        Parse the IPv4 protocol.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction.

        Returns:
            Tuple[str, str, str]: updated values of the arguments nft_rule, callback_funcs, nft_rule_backwards
        """
        # Handle IPv4 source address
        if 'src' in data:
            ip = data['src'] if data['src'] != "self" else self.device['ip']
            nft_rule += f"ip saddr {ip} "
            # Handle backwards direction
            if nft_rule_backwards:
                nft_rule_backwards += f"ip daddr {ip} "
        # Handle IPv4 destination address
        if 'dst' in data:
            ip = data['dst'] if data['dst'] != "self" else self.device['ip']
            nft_rule += f"ip daddr {ip} "
            # Handle backwards direction
            if nft_rule_backwards:
                nft_rule_backwards += f"ip saddr {ip} "

        return nft_rule, callback_funcs, nft_rule_backwards
