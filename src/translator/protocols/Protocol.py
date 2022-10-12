import jinja2
import importlib

class Protocol:
    """
    Generic protocol, inherited by all concrete protocols.
    """
    
    def __init__(self, device: str, policy: str, env: jinja2.Environment) -> None:
        """
        Generic protocol constructor.

        Args:
            device (dict): Device data from the YAML profile.
            policy (str): Policy name.
            env (jinja2.Environment): Jinja2 environment.
        """
        self.device = device
        self.policy = policy
        self.scenario = policy.replace("-", "_")
        self.nft_table_chain = f"netdev {device['name']} {policy}"
        self.env = env

    @classmethod
    def init_protocol(c, protocol_name: str, device: dict, policy: str, env: jinja2.Environment):
        """
        Factory method for a specific protocol.

        Args:
            protocol_name (str): Name of the protocol.
            device (dict): Device data from the YAML profile.
            policy (str): Policy name.
            env (jinja2.Environment): Jinja2 environment.
        """
        module = importlib.import_module(f"protocols.{protocol_name}")
        cls = getattr(module, protocol_name)
        return cls(device, policy, env)

    def parse(self, data: dict, nft_rule: str, callback_funcs: str, nft_rule_backwards = "") -> str:
        """
        Default parsing method, returns the arguments values unchanged.

        Args:
            data (dict): Data from the YAML profile.
            nft_rule (str): Current nftables rule (unused by HTTP).
            callback_funcs (str): Current callback functions to be written in the C file.
            nft_rule_backwards (str): Current nftables rule for the backwards direction.

        Returns:
            Tuple[str, str, str]: updated values of the arguments nft_rule, callback_funcs, nft_rule_backwards
        """
        return nft_rule, callback_funcs, nft_rule_backwards
