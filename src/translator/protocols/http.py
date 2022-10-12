from typing import Tuple
from protocols.Application import Application

class http(Application):
    
    # Class variables
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "request-type",
        "uri"
    ]

    def parse(self, data: dict, states: dict, accumulators: dict) -> None:
        """
        Parse the HTTP protocol.

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
        
        # Handle HTTP request type
        method = data["method"]
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.method == {method}"
        # Handle HTTP URI
        uri = data["uri"]
        callback_dict["match_a"] += f" &&\n\t\tstrcmp(message.uri, \"{uri}\") == 0"

        # Update callback functions accumulator
        accumulators["callback_funcs"] = accumulators.get("callback_funcs", "") + callback_tpl.render(callback_dict)
