from protocols.Application import Application

class dns(Application):
    
    # Class variables
    protocol_name = "dns"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",        # DNS query type
        "domain-name"  # DNS domain name
    ]

    def handle_fields(self, data: dict, callback_dict: dict, direction_both = False) -> None:
        """
        Handle the different protocol fields.

        Args:
            data (dict): Data from the YAML profile.
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
            direction_both (bool): Whether the rule should be applied in both directions.
        """
        callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.qr == 0"
        if direction_both:
            # Handle backwards direction
            callback_dict["match_b"] = callback_dict.get("match_b", "") + f" &&\n\t\tmessage.qr == 1"
        # Handle DNS query type
        if 'type' in data:
            query_type = data["type"]
            callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tmessage.questions->qtype == {query_type}"
            if direction_both:
                # Handle backwards direction
                callback_dict["match_b"] = callback_dict.get("match_b", "") + f" &&\n\t\tmessage.questions->qtype == {query_type}"
        # Handle DNS domain name
        if 'domain-name' in data:
            domain_name = data["domain-name"]
            callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\tdns_contains_domain_name(message.questions, message.header.qdcount, \"{domain_name}\")"
            if direction_both:
                # Handle backwards direction
                callback_dict["match_b"] = callback_dict.get("match_b", "") + f" &&\n\t\tdns_contains_domain_name(message.questions, message.header.qdcount, \"{domain_name}\")"
