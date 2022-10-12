from protocols.Application import Application

class http(Application):
    
    # Class variables
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "request-type",
        "uri"
    ]

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> str:
        """
        Parse the HTTP protocol.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction (unused by HTTP).

        Returns:
            Tuple[str, str, str]: updated values of the arguments nft_rule, callback_funcs, nft_rule_backwards
        """
        # Initialize Jinja2 template for callback function
        callback_tpl = self.env.get_template("callback.c.j2")
        callback_dict = {"scenario": self.scenario, "protocol": self.protocol_name}

        # Handle state
        callback_dict["match_a"] = "state == STATE_A &&\n\t\t"
        callback_dict["match_b"] = "state == STATE_B"
        
        # Handle HTTP request type
        method = data["method"]
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f"message.method == {method} &&\n\t\t"
        # Handle HTTP URI
        uri = data["uri"]
        callback_dict["match_a"] += f"strcmp(message.uri, \"{uri}\") == 0"

        # Render and concatenate callback function
        return nft_rule, callback_funcs + callback_tpl.render(callback_dict), nft_rule_backwards
