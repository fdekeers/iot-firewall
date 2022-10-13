from protocols.Application import Application

class dns(Application):
    
    # Class variables
    protocol_name = "dns"  # Protocol name

    # Supported keys in YAML profile
    supported_keys = [
        "type",        # DNS query type
        "domain-name"  # DNS domain name
    ]

    def handle_app_fields(self) -> None:
        """
        Handle the different protocol fields.

        Args:
            direction_both (bool): Whether the rule should be applied in both directions.
        """
        # Profile DNS rules will always be queries
        self.callback_dict["match_a"] = self.callback_dict.get("match_a", "") + f" &&\n\t\tmessage.qr == 0"
        if self.parsing_data['accumulators']['nft_rule_backwards']:
            # Handle backwards direction
            self.callback_dict["match_b"] = self.callback_dict.get("match_b", "") + f" &&\n\t\tmessage.qr == 1"
        # Handle DNS query type
        rules = {"forward": "message.questions->qtype == {}", "backward": "message.questions->qtype == {}"}
        self.add_field("qtype", rules)
        # Handle DNS domain name
        rules = {"forward": "dns_contains_domain_name(message.questions, message.header.qdcount, \"{}\"", "backward": "dns_contains_domain_name(message.questions, message.header.qdcount, \"{}\""}
        self.add_field("domain-name", rules)
