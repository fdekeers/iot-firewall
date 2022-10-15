from ast import Call
from typing import Callable
from protocols.Protocol import Protocol

class Custom(Protocol):

    # Class variables
    layer = 7             # Protocol OSI layer
    custom_parser = True  # Whether the protocol has a custom parser


    def add_field(self, field: str, rules: dict, func = lambda x: x, backward_func = lambda x: x) -> None:
        """
        Add a new custom parser rule to the callback function.
        Overrides the nftables version.

        Args:
            field (str): Field to add the rule for.
            rules (dict): Dictionary containing the custom matches for the C file.
            func (lambda): Function to apply to the field value before writing it.
                           Optional, default is the identity function.
            backward_func (lambda): Function to apply to the field value in the case of a backwards rule.
                           Will be applied before the forward function.
                           Optional, default is the identity function.
        """
        if field in self.parsing_data['profile_data']:
            value = self.parsing_data['profile_data'][field]
            self.callback_dict["match_a"] = self.callback_dict.get("match_a", "") + f" &&\n\t\t{rules['forward'].format(func(value))}"
            if "backward" in rules and self.parsing_data['accumulators']['nft_rule_backwards']:
                self.callback_dict["match_b"] = self.callback_dict.get("match_b", "") + f" &&\n\t\t{rules['backward'].format(func(backward_func(value)))}"


    def handle_app_fields(self, direction_both = False) -> None:
        """
        Handle the different custom protocols fields.
        Must be overridden by the child class.

        Args:
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
            direction_both (bool): Whether the rule should be applied in both directions.
        """
        pass


    def parse(self) -> None:
        """
        Parse a protocol with custom parser.
        Updates the accumulator values for the nftables and custom C rules.
        """
        # Initialize Jinja2 template for callback function
        callback_tpl = self.env.get_template("callback.c.j2")
        self.callback_dict = {"scenario": self.metadata['scenario'], "protocol": self.metadata['protocol']}

        # Handle state
        self.callback_dict["old_state"] = self.parsing_data['states']['old']
        self.callback_dict["new_state"] = self.parsing_data['states']['new']
        
        # Handle protocol fields
        self.handle_app_fields()

        # Update callback functions accumulator
        accumulators = self.parsing_data['accumulators']
        accumulators['callback_funcs'] = accumulators.get("callback_funcs", "") + callback_tpl.render(self.callback_dict)    
