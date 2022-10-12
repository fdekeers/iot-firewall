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

    def handle_fields(self, data: dict, callback_dict: dict) -> None:
        """
        Handle the different protocol fields.

        Args:
            data (dict): Data from the YAML profile.
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
        """
        # Handle HTTP request type
        method = data["method"]
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.method == {method}"
        # Handle HTTP URI
        uri = data["uri"]
        callback_dict["match_a"] += f" &&\n\t\tstrcmp(message.uri, \"{uri}\") == 0"
