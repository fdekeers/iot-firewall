from protocols.Application import Application

class http(Application):
    
    # Class variables
    protocol_name = "http"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "request-type",
        "uri"
    ]

    def handle_app_fields(self) -> None:
        """
        Handle the different protocol fields.
        """
        # Profile HTTP rules will always be requests
        self.callback_dict["match_a"] = self.callback_dict.get("match_a", "") + f" &&\n\t\tmessage.is_request"
        if self.parsing_data['accumulators']['nft_rule_backwards']:
            # Handle backwards direction
            self.callback_dict["match_b"] = self.callback_dict.get("match_b", "") + f" &&\n\t\t!message.is_request"
        # Handle HTTP method
        rules = {"forward": "message.method == {}"}
        self.add_field("method", rules)
        # Handle HTTP URI
        rules = {"forward": "strcmp(message.uri, \"{}\") == 0"}
        self.add_field("uri", rules)
