from protocols.Protocol import Protocol

class Policy:
    """
    Class which represents a single access control policy.
    """

    # Statistics currently handled
    stats_templates = {
        "rate": "limit rate {}",
        "packet-size": "meta length {}",
        "packet-count": "counter name {}"
    }

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
        self.counters = {}                          # Counters associated to this policy (will be populated by parsing)

    
    def is_periodic(self) -> bool:
        """
        Check whether the policy represents a periodic pattern.
        """
        return "stats" in self.profile_data and "rate" in self.profile_data["stats"]

    
    def handle_stat(self, stat: str) -> None:
        """
        Add the nftables match corresponding to the given stat to this policy's rule.

        Args:
            stat (str): Statistic to handle
        """
        value = self.profile_data["stats"][stat]
        if type(value) == dict:
            # Stat is a dictionary, and contains data for directions "out" and "in"
            value_out = value["out"]
            value_in = value["in"]
            if stat == "packet-count":
                # Add counters for "out" and "in" directions
                self.counters["out"] = value_out
                self.counters["in"] = value_in
                # Update values with counter names (to be used as nftables match)
                value_out = f"{self.name}-out"
                value_in = f"{self.name}-in"
            match_forward = Policy.stats_templates[stat].format(value_out)
            match_backward = Policy.stats_templates[stat].format(value_in)
            self.nft_matches.append({"forward": match_forward, "backward": match_backward})
        else:
            # Stat is a single value
            if stat == "packet-count":
                self.counters["default"] = value
                value = self.name
            match = Policy.stats_templates[stat].format(value)
            self.nft_matches.append({"forward": match, "backward": match})

    
    def build_nft_rule(self, queue_num: int) -> dict:
        """
        Build the nftables rules (forward and backward) for this policy.

        Args:
            queue_num (int): Number of the nfqueue queue corresponding to this policy,
                             or a negative number if the policy does not need an nfqueue.
        Returns:
            dict: Dictionary containing the forward and backward nftables rules
        """
        # Packet header matching
        nft_rule_forward = ""
        nft_rule_backward = ""
        for i in range(len(self.nft_matches)):
            if i > 0:
                nft_rule_forward += " "
            nft_rule_forward += f"{self.nft_matches[i]['forward']}"
            # Add backward rule (if necessary)
            if self.direction == "both" and "backward" in self.nft_matches[i]:
                if i > 0:
                    nft_rule_backward += " "
                nft_rule_backward += f"{self.nft_matches[i]['backward']}"

        # Finalize rule
        suffix = f" queue num {queue_num}" if queue_num >= 0 else " accept"
        nft_rule_forward += suffix
        rule = {"forward": nft_rule_forward}
        if self.direction == "both" and nft_rule_backward:
            nft_rule_backward += suffix
            rule["backward"] = nft_rule_backward
        return rule

    
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
        
        # Parse statistics
        if "stats" in self.profile_data:
            packet_count_idx = -1  # Index of the packet-count rule (-1 if not present)
            for stat in self.profile_data["stats"]:
                if stat in Policy.stats_templates:
                    self.handle_stat(stat)
                    if stat == "packet-count":
                        packet_count_idx = len(self.nft_matches) - 1
            if packet_count_idx >= 0:
                # Rules contain packet-count stat
                # Move packet-count match to the end of the list
                packet_count_match = self.nft_matches.pop(packet_count_idx)
                self.nft_matches.append(packet_count_match)
