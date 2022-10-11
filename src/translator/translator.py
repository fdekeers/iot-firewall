import argparse
from pathlib import Path
import yaml
import jinja2
import csnake
import importlib


def init_protocol(protocol_name: str):
    """
    Initialize a protocol.

    Args:
        protocol_name (str): Name of the protocol.

    Returns:
        Protocol: Protocol object.
    """
    module = importlib.import_module(f"protocols.{protocol_name}")
    cls = getattr(module, protocol_name)
    return cls()


if __name__ == "__main__":

    # Commande line arguments
    description = "Translate a device YAML profile to a corresponding nfqueue C code"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("profile", help="Path to the device YAML profile")
    args = parser.parse_args()

    # Jinja loader
    loader = jinja2.FileSystemLoader(searchpath="templates")
    env = jinja2.Environment(loader=loader)

    # Load the device profile
    with open(args.profile, "r") as f:
        profile = yaml.safe_load(f)
        
        # Create device directory
        dir = profile["device-info"]["device-name"]
        Path(dir).mkdir(exist_ok=True)

        # Header meta-information
        header_tpl = env.get_template("header.c.j2")
        header_dict = {"device": profile["device-info"]["device-name"]}

        # Loop over the device's policies
        # Individual policies
        nfq_id_base = 0
        for policy in profile["individual-policies"]:
            value = profile["individual-policies"][policy]
            scenario = policy.replace("-", "_")

            # Populate meta-information and constants
            header_dict["scenario"] = scenario
            header_dict["max_threads"] = 1
            header_dict["num_states"] = 2
            header_dict["nfq_id_base"] = nfq_id_base
            nfq_id_base += 10

            protocol_name = list(value["protocols"].keys())[0]
            header_dict["parsers"] = header_dict.get("parsers", "") + f"#include \"parsers/{protocol_name}.h\"\n"

            # Render header
            header = header_tpl.render(header_dict)

            # Populate callback function
            callback_tpl = env.get_template("callback.c.j2")
            callback_dict = {"scenario": scenario, "protocol": protocol_name}

            # Protocol decoding
            protocol = init_protocol(protocol_name)
            protocol.parse(value["protocols"][protocol_name], callback_dict)

            callback = callback_tpl.render(callback_dict)

            # Populate main function
            main_tpl = env.get_template("main.c.j2")
            main = main_tpl.render(scenario=scenario, nfq_id_offset=0)

            # Write full file
            with open(f"{dir}/{policy}.c", "w+") as fw:
                fw.write(header)
                fw.write(callback)
                fw.write(main)

        # Interaction policies
        """
        for policy in profile["interaction-policies"]:
            a = 1
        """
