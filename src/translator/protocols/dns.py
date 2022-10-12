from typing import Tuple
from protocols.Application import Application

class dns(Application):
    
    # Class variables
    protocol_name = "dns"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",        # DNS query type
        "domain-name"  # DNS domain name
    ]

    def parse(self, data: dict, states: dict, accumulators: dict) -> None:
        """
        Parse the DNS protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Initialize Jinja2 template for callback function
        callback_tpl = self.env.get_template("callback.c.j2")
        callback_dict = {"scenario": self.scenario, "protocol": self.protocol_name}

        # Handle state
        callback_dict["old_state"] = states["old"]
        callback_dict["new_state"] = states["new"]
        
        # Handle DNS query type
        query_type = data["type"]
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.questions->qtype == {query_type}"
        # Handle DNS domain name
        domain_name = data["domain-name"]
        callback_dict["match_a"] += f" &&\n\t\tdns_contains_domain_name(message.questions, message.header.qdcount, \"{domain_name}\")"

        # Update callback functions accumulator
        accumulators["callback_funcs"] = accumulators.get("callback_funcs", "") + callback_tpl.render(callback_dict)
