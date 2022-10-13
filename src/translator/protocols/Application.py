from protocols.Protocol import Protocol

class Application(Protocol):

    # Class variables
    layer = 7             # Protocol OSI layer
    custom_parser = True  # Whether the protocol has a custom parser

    def add_field(self, field: str, data: dict, callback_dict: dict) -> None:
        """
        Add a new rule to the callback function.

        Args:
            field (str): Field to add the rule for..
            data (dict): Data from the YAML profile.
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
        """
        if field in data:
            callback_dict["match_a"] = callback_dict.get("match_a", "") + f" &&\n\t\t{field} == {data[field]}"

    def handle_fields(self, callback_dict: dict, direction_both = False) -> None:
        """
        Handle the different protocol fields.
        Must be overridden by the child class.

        Args:
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
            direction_both (bool): Whether the rule should be applied in both directions.
        """
        pass

    def parse(self) -> None:
        """
        Parse the DNS protocol.
        Updates the accumulator values for the nftables and custom C rules.
        """
        # Initialize Jinja2 template for callback function
        callback_tpl = self.env.get_template("callback.c.j2")
        callback_dict = {"scenario": self.metadata['scenario'], "protocol": self.metadata['protocol']}

        # Handle state
        callback_dict["old_state"] = self.parsing_data['states']['old']
        callback_dict["new_state"] = self.parsing_data['states']['new']
        
        # Handle protocol fields
        self.handle_fields(callback_dict, "nft_rule_backwards" in self.parsing_data['accumulators'])

        # Update callback functions accumulator
        accumulators = self.parsing_data['accumulators']
        accumulators['callback_funcs'] = accumulators.get("callback_funcs", "") + callback_tpl.render(callback_dict)    
