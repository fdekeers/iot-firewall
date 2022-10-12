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

    def handle_fields(self, data: dict, callback_dict: dict) -> None:
        """
        Handle the different protocol fields.

        Args:
            data (dict): Data from the YAML profile.
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
        """
        # Handle DNS query type
        query_type = data["type"]
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.questions->qtype == {query_type}"
        # Handle DNS domain name
        domain_name = data["domain-name"]
        callback_dict["match_a"] += f" &&\n\t\tdns_contains_domain_name(message.questions, message.header.qdcount, \"{domain_name}\")"
