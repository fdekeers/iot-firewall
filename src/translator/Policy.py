from protocols.Protocol import Protocol

class Policy:
    """
    Class which represents a single access control policy.
    """

    def __init__(self, name: str, profile_data: dict, device: dict) -> None:
        """
        Initializes a new Policy object.

        Args:
            name (str): Name of the policy.
            profile_data (dict): Dictionary containing the policy data from the YAML profile.
        """
        self.name = name
        self.profile_data = profile_data
        self.device = device
        self.included_parsers = []

    
    def parse(self) -> dict:
        # Initialize accumulators for nftables and Jinja2
        accumulators = {
            "nft": [],
            "nfq": [],
            "jinja": {
                "header": {},
                "callback": {},
                "main": {}
            }
        }
        # Parse protocols
        for protocol_name in self.profile_data["protocols"]:
            protocol = Protocol.init_protocol(protocol_name, self.profile_data["protocols"][protocol_name], self.device)
            if protocol.custom_parser:
                accumulators["jinja"]["callback"]["protocol"] = protocol_name
                accumulators["jinja"]["main"]["protocol"] = protocol_name
                if protocol_name not in self.included_parsers:
                    accumulators["jinja"]["header"]["parsers"] = accumulators["jinja"]["header"].get( "parsers", "") + f"#include \"parsers/{protocol_name}.h\"\n"
                    self.included_parsers.append(protocol_name)
            new_rules = protocol.parse(self.profile_data["direction"])
            accumulators["nft"].extend(new_rules["nft"])
            accumulators["nfq"].extend(new_rules["nfq"])
        return accumulators
