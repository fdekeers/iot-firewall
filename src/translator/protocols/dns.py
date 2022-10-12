from protocols.Application import Application

class dns(Application):
    
    # Class variables
    protocol_name = "dns"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",        # DNS query type
        "domain-name"  # DNS domain name
    ]

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> str:
        """
        Parse the DNS protocol.

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
        
        # Handle DNS query type
        query_type = data["type"]
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f"message.questions->qtype == {query_type} &&\n\t\t"
        # Handle DNS domain name
        domain_name = data["domain-name"]
        callback_dict["match_a"] += f"dns_contains_domain_name(message.questions, message.header.qdcount, \"{domain_name}\")"

        # Render and concatenate callback function
        return nft_rule, callback_funcs + callback_tpl.render(callback_dict), nft_rule_backwards
