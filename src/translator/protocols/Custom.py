from protocols.Protocol import Protocol

class Custom(Protocol):

    # Class variables
    custom_parser = True  # Whether the protocol has a custom parser

    def add_field(self, field: str, template_rules: dict, is_backward: bool = False, func = lambda x: x, backward_func = lambda x: x) -> None:
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
                           Will be applied after `func`.
                           Optional, default is the identity function.
        """
        if field in self.protocol_data:
            value = self.protocol_data[field]
            rules = {}

            # If value from YAML profile is a list, produce disjunction of all elements
            if type(value) == list:
                template = "( "
                match = []
                # Value is a list
                for i in range(len(value)):
                    if i != 0:
                        template += " || "
                    if not is_backward:
                        template += template_rules["forward"]
                        match.append(func(value[i]))
                    elif is_backward and "backward" in template_rules:
                        template += template_rules["backward"]
                        match.append(backward_func(func(value[i])))
                rules = {"template": f"{template} )", "match": match}
            else:
                # Value is a single element
                if not is_backward:
                    rules = {"template": template_rules["forward"], "match": func(value)}
                elif is_backward and "backward" in template_rules:
                    rules = {"template": template_rules["backward"], "match": backward_func(func(value))}

            # Append rules
            if rules:
                self.rules["nfq"].append(rules)
