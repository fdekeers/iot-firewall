import jinja2
from protocols.Layer4 import Layer4

class udp(Layer4):
    
    # Class variables
    protocol_name = "udp"  # Protocol name

    def __init__(self, device: str, policy: str, env: jinja2.Environment) -> None:
        """
        Constructor for the TCP protocol.

        Args:
            device (dict): Device data from the YAML profile.
            policy (str): Policy name.
            env (jinja2.Environment): Jinja2 environment.
        """
        super().__init__(device, policy, env)

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> str:
        """
        Parse the TCP protocol.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction.
        """
        return super().parse(data, nft_rule, callback_funcs, nft_rule_backwards)
