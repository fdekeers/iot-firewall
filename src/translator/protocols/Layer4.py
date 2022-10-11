import jinja2
from protocols.Protocol import Protocol

class Layer4(Protocol):
    
    # Class variables
    layer = 4              # Protocol OSI layer
    custom_parser = False  # Whether the protocol has a custom parser

    # Supported keys in YAML profile
    supported_keys = [
        "src-port",
        "dst-port"
    ]

    def __init__(self, device: str, policy: str, env: jinja2.Environment) -> None:
        """
        Constructor for any layer 4 protocol.

        Args:
            device (dict): Device data from the YAML profile.
            policy (str): Policy name.
            env (jinja2.Environment): Jinja2 environment.
        """
        super().__init__(device, policy, env)

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
