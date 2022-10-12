from typing import Tuple
from protocols.Protocol import Protocol

class icmp(Protocol):

    # Class variables
    protocol_name = "icmp"  # Protocol name
    layer = 3               # Protocol OSI layer
    custom_parser = False   # Whether the protocol has a custom parser
    
    # Supported keys in YAML profile
    supported_keys = [
        "type"  # ICMP message type
    ]

    @staticmethod
    def flip_echo_type(echo_type: str) -> str:
        """
        Flip the given ICMP echo type.

        Args:
            echo_type (str): ICMP echo type.

        Returns:
            str: 'echo-reply' if the given type was 'echo-request',
                 'echo-request' if the given type was 'echo-reply'.
        """
        if echo_type == "echo-request":
            return "echo-reply"
        elif echo_type == "echo-reply":
            return "echo-request"

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> Tuple[str, str, str]:
        """
        Parse the ICMP protocol.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction.

        Returns:
            Tuple[str, str, str]: updated values of the arguments nft_rule, callback_funcs, nft_rule_backwards
        """
        # Handle ICMP message type
        if 'type' in data:
            icmp_type = data['type']
            nft_rule += f"icmp type {icmp_type} "
            if nft_rule_backwards and "echo" in icmp_type:
                nft_rule_backwards += f"icmp type {self.flip_echo_type(icmp_type)} "

        return nft_rule, callback_funcs, nft_rule_backwards
