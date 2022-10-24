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
        self.name = name                            # Policy name
        self.profile_data = profile_data            # Policy data from the YAML profile
        self.direction = profile_data["direction"]  # Policy direction
        self.device = device                        # Name of the device this policy is linked to
        self.custom_parser = ""                     # Name of the custom parser (if any)
        self.nft_matches = []                       # List of nftables matches (will be populated by parsing)
        self.nfq_matches = []                       # List of nfqueue matches (will be populated by parsing)
        self.periodic = self.is_periodic()          # Whether the policy represents a periodic pattern

    
    def is_periodic(self) -> bool:
        """
        Check whether the policy represents a periodic pattern.
        """
        return "stats" in self.profile_data and "rate" in self.profile_data["stats"]

    
    def parse(self) -> None:
        """
        Parse the policy and populate the related instance variables
        """
        # Parse protocols
        for protocol_name in self.profile_data["protocols"]:
            protocol = Protocol.init_protocol(protocol_name, self.profile_data["protocols"][protocol_name], self.device)
            if protocol.custom_parser:
                self.custom_parser = protocol_name
            new_rules = protocol.parse(self.profile_data["direction"])
            self.nft_matches += new_rules["nft"]
            self.nfq_matches += new_rules["nfq"]
