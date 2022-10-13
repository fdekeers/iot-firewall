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

    def parse(self) -> None:
        """
        Parse the ICMP protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Handle ICMP message type
        if 'type' in self.parsing_data['profile_data']:
            icmp_type = self.parsing_data['profile_data']['type']
            self.parsing_data['accumulators']["nft_rule"] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']} ") + f"icmp type {icmp_type} "
            if "nft_rule_backwards" in self.parsing_data['accumulators'] and "echo" in icmp_type:
                self.parsing_data['accumulators']["nft_rule_backwards"] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']} ") + f"icmp type {self.flip_echo_type(icmp_type)} "
