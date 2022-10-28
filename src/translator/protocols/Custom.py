from protocols.Protocol import Protocol

class Custom(Protocol):

    # Class variables
    custom_parser = True  # Whether the protocol has a custom parser

    def add_field(self, field: str, template_rules: dict, direction: str = "in", func= lambda x: x, backward_func = lambda x: x) -> None:
        """
        Add a new nfqueue match to the accumulator.
        Overrides the nftables version.

        Args:
            field (str): Field to add the rule for.
            template_rules (dict): Dictionary containing the protocol-specific rules to add.
            direction (str): Direction of the traffic (in, out, or both). Default is "in".
            func (lambda): Function to apply to the field value before writing it.
                           Optional, default is the identity function.
            backward_func (lambda): Function to apply to the field value in the case of a backwards rule.
                           Will be applied after the forward function.
                           Optional, default is the identity function.
        """
        if field in self.protocol_data:
            value = self.protocol_data[field]
            rules = {}

            # If value from YAML profile is a list, produce disjunction of all elements
            if type(value) == list:
                rules["forward"] = "( "
                # Value is a list
                for i in range(len(value)):
                    if i != 0:
                        rules["forward"] += " || "
                    rules["forward"] += template_rules["forward"].format(func(value[i]))
                    if "backward" in template_rules and direction == "both":
                        backward_rule = template_rules["backward"].format(backward_func(func(value[i])))
                        rules["backward"] = rules["backward"] + f" || {backward_rule}" if "backward" in rules else f"( {backward_rule}"
                rules["forward"] += " )"
                if "backward" in rules:
                    rules["backward"] += " )"
            else:
                # Value is a single element
                rules["forward"] = template_rules["forward"].format(func(value))
                if "backward" in template_rules and direction == "both":
                    rules["backward"] = template_rules["backward"].format(backward_func(func(value)))

            # Write forward rule
            self.rules["nfq"].append(rules)