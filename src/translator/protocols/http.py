from urllib import request
import jinja2

class http:
    
    # Supported keys in YAML profile
    supported_keys = [
        "request-type",
        "uri"
    ]

    def __init__(self,):
        """
        Initialize the HTTP protocol.
        """
        pass

    def parse(self, data: dict, template: dict):
        """
        Parse the HTTP protocol.

        Args:
            data (dict): Data from the YAML profile.
            template (dict): Template dictionary.
        """
        # Initialize match A
        template["match_a"] = "state == STATE_A &&\n\t\t"
        # Handle HTTP request type
        method = data["method"]
        template["match_a"] += f"message.method == {method} &&\n\t\t"
        # Handle HTTP URI
        uri = data["uri"]
        template["match_a"] += f"strcmp(message.uri, \"{uri}\") == 0"

        # Initialize match B
        template["match_b"] = "state == STATE_B"
