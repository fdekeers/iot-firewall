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

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> str:
        """
        Parse a layer 4 protocol.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction.
        """
        # Handle TCP source and destination ports
        nft_rule += f"{self.protocol_name} sport {data['src-port']} " if 'src-port' in data else ""
        nft_rule += f"{self.protocol_name} dport {data['dst-port']} " if 'dst-port' in data else ""
        # Handle backwards direction
        if nft_rule_backwards:
            nft_rule_backwards += f"{self.protocol_name} sport {data['dst-port']} " if 'dst-port' in data else ""
            nft_rule_backwards += f"{self.protocol_name} dport {data['src-port']} " if 'src-port' in data else ""

        return nft_rule, callback_funcs, nft_rule_backwards
