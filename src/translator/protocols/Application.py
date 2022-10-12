from protocols.Protocol import Protocol

class Application(Protocol):

    # Class variables
    layer = 7             # Protocol OSI layer
    custom_parser = True  # Whether the protocol has a custom parser

    def handle_fields(self, data: dict, callback_dict: dict) -> None:
        """
        Handle the different protocol fields.
        Must be overridden by the child class.

        Args:
            data (dict): Data from the YAML profile.
            callback_dict (dict): Dictionary containing the Jinja2 template variables for the callback function.
        """
        pass

    def parse(self, data: dict, states: dict, accumulators: dict) -> None:
        """
        Parse the DNS protocol.

        Args:
            data (dict): Data from the YAML profile.
            states (dict): Current and next states.
            accumulators (dict): Dictionary containing the accumulators for the forward and backward nftables rules and the callback functions.
        """
        # Initialize Jinja2 template for callback function
        callback_tpl = self.env.get_template("callback.c.j2")
        callback_dict = {"scenario": self.scenario, "protocol": self.protocol_name}

        # Handle state
        callback_dict["old_state"] = states["old"]
        callback_dict["new_state"] = states["new"]
        
        # Handle protocol fields
        self.handle_fields(data, callback_dict)

        # Update callback functions accumulator
        accumulators["callback_funcs"] = accumulators.get("callback_funcs", "") + callback_tpl.render(callback_dict)    
