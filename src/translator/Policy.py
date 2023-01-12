from typing import Dict
from protocols.Protocol import Protocol

class Policy:
    """
    Class which represents a single access control policy.
    """

    # Enum values
    MATCH = 0
    ACTION = 1

    # Metadata for supported nftables statistics
    stats_metadata = {
        "rate": {"type": MATCH, "counter": False, "template": "limit rate {}"},
        "packet-size": {"type": MATCH, "counter": False, "template": "meta length {}"},
        "packet-count": {"type": ACTION, "counter": True, "template": "counter name {}"},
        "duration": {"counter": True}
    }

    def __init__(self, policy_name: str, profile_data: dict, device: dict, is_backward = False) -> None:
        """
        Initialize a new Policy object.

        Args:
            name (str): Name of the policy.
            profile_data (dict): Dictionary containing the policy data from the YAML profile.
            device (dict): Dictionary containing the device metadata from the YAML profile.
            is_backward (bool): Whether the policy is backwards (i.e. the source and destination are reversed).
        """
        self.name = policy_name                     # Policy name
        self.profile_data = profile_data            # Policy data from the YAML profile
        self.is_backward = is_backward              # Whether the policy is backwards (i.e. the source and destination are reversed)
        self.initiator = profile_data["initiator"] if "initiator" in profile_data else ""
        self.device = device                        # Name of the device this policy is linked to
        self.custom_parser = ""                     # Name of the custom parser (if any)
        self.nft_matches = []                       # List of nftables matches (will be populated by parsing)
        self.nft_stats = {}                         # Dict of nftables statistics (will be populated by parsing)
        self.nft_match = ""   # Complete nftables match (including rate and packet size)
        self.nft_action = ""  # nftables action associated to this policy (including counters)
        self.nfq_matches = []                       # List of nfqueue matches (will be populated by parsing)
        self.transient = self.is_transient()        # Whether the policy represents a transient pattern
        self.periodic = self.is_periodic()          # Whether the policy represents a periodic pattern
        self.counters = {}                          # Counters associated to this policy (will be populated by parsing)

    
    def is_transient(self) -> bool:
        """
        Check whether the policy represents a transient pattern.
        """
        return "stats" in self.profile_data and ("duration" in self.profile_data["stats"] or "packet-count" in self.profile_data["stats"])


    def is_periodic(self) -> bool:
        """
        Check whether the policy represents a periodic pattern.
        """
        return "stats" in self.profile_data and "rate" in self.profile_data["stats"] and ("duration" not in self.profile_data["stats"] or "packet-count" not in self.profile_data["stats"])

    
    def parse_stat(self, stat: str) -> Dict[str, str]:
        """
        Parse a single statistic.
        Add the corresponding counters and nftables matches.

        Args:
            stat (str): Statistic to handle
        Returns:
            dict: parsed stat, with the form {"template": ..., "match": ...}
        """
        parsed_stat = None
        value = self.profile_data["stats"][stat]
        if type(value) == dict:
            # Stat is a dictionary, and contains data for directions "out" and "in"
            value_out = value["out"]
            value_in = value["in"]
            if Policy.stats_metadata[stat]["counter"]:
                # Add counters for "out" and "in" directions
                self.counters[stat] = {
                    "out": value_out,
                    "in": value_in
                }
                # If stat is packet count, update values with counter names (to be used as nftables match)
                if stat == "packet-count":
                    value_out = f"\"{self.name}-out\""
                    value_in = f"\"{self.name}-in\""
            if stat in Policy.stats_metadata and "template" in Policy.stats_metadata[stat]:
                parsed_stat = {
                    "template": Policy.stats_metadata[stat]["template"],
                    "match": value_in if self.is_backward else value_out,
                }
        else:
            # Stat is a single value, which is used for both directions
            if Policy.stats_metadata[stat]["counter"]:
                self.counters[stat] = {"default": value}
                value = f"\"{self.name}\""
            if stat in Policy.stats_metadata and "template" in Policy.stats_metadata[stat]:
                parsed_stat = {
                    "template": Policy.stats_metadata[stat]["template"],
                    "match": value
                }
        
        return parsed_stat

    
    def build_nft_rule(self, queue_num: int) -> str:
        """
        Build and store the nftables match and action, as strings, for this policy.

        Args:
            queue_num (int): Number of the nfqueue queue corresponding to this policy,
                             or a negative number if the policy is simply `accept`
        Returns:
            str: complete nftables rule for this policy
        """
        # nftables match
        for i in range(len(self.nft_matches)):
            if i > 0:
                self.nft_match += " "
            template = self.nft_matches[i]["template"]
            data = self.nft_matches[i]["match"]
            self.nft_match += template.format(*(data)) if type(data) == list else template.format(data)

        # nftables stats
        for stat in self.nft_stats:
            template = self.nft_stats[stat]["template"]
            data = self.nft_stats[stat]["match"]
            if "type" in Policy.stats_metadata[stat] and Policy.stats_metadata[stat]["type"] == Policy.MATCH:
                self.nft_match += " " + template.format(*(data)) if type(data) == list else template.format(data)
            elif "type" in Policy.stats_metadata[stat] and Policy.stats_metadata[stat]["type"] == Policy.ACTION:
                self.nft_action += template.format(*(data)) if type(data) == list else template.format(data) + " "

        # nftables action
        self.nft_action = f"queue num {queue_num}" if queue_num >= 0 else "accept"

        return self.get_nft_rule()

    
    def get_nft_rule(self) -> str:
        """
        Retrieve the complete nftables rule, composed of the complete nftables match
        and the action, for this policy.

        Returns:
            str: complete nftables rule for this policy
        """
        return f"{self.nft_match} {self.nft_action}"

    
    def parse(self) -> None:
        """
        Parse the policy and populate the related instance variables.
        """
        # Parse protocols
        for protocol_name in self.profile_data["protocols"]:
            try:
                protocol = Protocol.init_protocol(protocol_name, self.profile_data["protocols"][protocol_name], self.device)
            except ModuleNotFoundError:
                # Unsupported protocol, skip it
                continue
            else:
                # Supported protocol, parse it
                if protocol.custom_parser:
                    self.custom_parser = protocol_name
                new_rules = protocol.parse(is_backward=self.is_backward, initiator=self.initiator)
                self.nft_matches += new_rules["nft"]
                self.nfq_matches += new_rules["nfq"]
        
        # Parse statistics
        if "stats" in self.profile_data:
            for stat in self.profile_data["stats"]:
                if stat in Policy.stats_metadata:
                    parsed_stat = self.parse_stat(stat)
                    if parsed_stat is not None:
                        self.nft_stats[stat] = parsed_stat
