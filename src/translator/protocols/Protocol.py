import jinja2
import importlib

class Protocol:
    """
    Generic protocol, inherited by all concrete protocols.
    """
    

    def __init__(self, metadata: dict, parsing_data: dict, env: jinja2.Environment) -> None:
        """
        Generic protocol constructor.

        Args:
            metadata (dict): Device and policy metadata.
            parsing_data (dict): Current parsing_data related to this protocol, will be updated when parsing.
            env (jinja2.Environment): Jinja2 environment.
        """
        metadata["scenario"] = metadata['policy'].replace("-", "_")
        metadata['nft_table_chain'] = f"netdev {metadata['device']['name']} {metadata['policy']}"
        self.metadata = metadata
        self.parsing_data = parsing_data
        self.env = env


    @classmethod
    def init_protocol(c, metadata: dict, parsing_data: dict, env: jinja2.Environment):
        """
        Factory method for a specific protocol.

        Args:
            metadata (dict): Device and policy metadata.
            parsing_data (dict): Current parsing_data related to this protocol, will be updated when parsing.
            env (jinja2.Environment): Jinja2 environment.
        """
        module = importlib.import_module(f"protocols.{metadata['protocol']}")
        cls = getattr(module, metadata['protocol'])
        return cls(metadata, parsing_data, env)

    
    def add_field(self, field: str, rules: dict) -> None:
        """
        Add a new match in the current nftables rule.

        Args:
            field (str): Field to add the rule for.
            rules (dict): Dictionary containing the nftables matches, forward and backward (if necessary), for the given field.
        """
        if field in self.parsing_data['profile_data']:
            value = self.parsing_data['profile_data'][field]
            self.parsing_data['accumulators']['nft_rule'] = self.parsing_data['accumulators'].get("nft_rule", f"nft add rule {self.metadata['nft_table_chain']}") + f" {rules['forward'].format(value)}"
            if "backward" in rules and self.parsing_data['accumulators']['nft_rule_backwards']:
                self.parsing_data['accumulators']['nft_rule_backwards'] = self.parsing_data['accumulators'].get("nft_rule_backwards", f"nft add rule {self.metadata['nft_table_chain']}") + f" {rules['backward'].format(value)}"


    def parse(self) -> None:
        """
        Default parsing method.
        Must be updayed in the children class.
        """
        return None
