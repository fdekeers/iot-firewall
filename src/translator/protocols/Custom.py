from protocols.Protocol import Protocol

class Custom(Protocol):

    # Class variables
    custom_parser = True  # Whether the protocol has a custom parser

    def add_field(self, field: str, rules: dict, direction: str = "in", func= lambda x: x, backward_func = lambda x: x) -> None:
        """
        Add a new nfqueue match to the accumulator.
        Overrides the nftables version.

        Args:
            field (str): Field to add the rule for.
            rules (dict): Dictionary containing the protocol-specific rules to add.
            direction (str): Direction of the traffic (in, out, or both). Default is "in".
            func (lambda): Function to apply to the field value before writing it.
                           Optional, default is the identity function.
            backward_func (lambda): Function to apply to the field value in the case of a backwards rule.
                           Will be applied after the forward function.
                           Optional, default is the identity function.
        """
        if field in self.protocol_data:
            value = self.protocol_data[field]
            # Write forward rule
            rule = {}
            rule["forward"] = rules["forward"].format(func(value))
            # Write backward rule (if necessary)
            if "backward" in rules and direction == "both":
                rule["backward"] = rules["backward"].format(
                    backward_func(func(value)))
            self.rules["nfq"].append(rule)

