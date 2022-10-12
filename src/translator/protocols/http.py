from protocols.Application import Application

class http(Application):
    
    # Class variables
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "request-type",
        "uri"
    ]

    def handle_fields(self, data: dict, callback_dict: dict, direction_both = False) -> None:
        """
        Handle the different protocol fields.

        Args:
            data (dict): Data from the YAML profile.
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
            direction_both (bool): Whether the rule should be applied in both directions.
        """
        # Handle HTTP request type
        if 'method' in data:
            method = data["method"]
            callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.is_request"
            callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.method == {method}"
            # Handle backwards direction
            if direction_both:
                callback_dict["match_b"] = callback_dict.get("match_b", "") + f" &&\n\t\t!message.is_request"
        # Handle HTTP URI
        if 'uri' in data:
            uri = data["uri"]
            callback_dict["match_a"] += f" &&\n\t\tstrcmp(message.uri, \"{uri}\") == 0"
