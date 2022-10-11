import argparse
from pathlib import Path
import yaml
import jinja2
import subprocess
import importlib


def init_protocol(protocol_name: str, device: dict, policy: str, env: jinja2.Environment):
    """
    Initialize a protocol.

    Args:
        protocol_name (str): Name of the protocol.

    Returns:
        Protocol: Protocol object.
    """
    module = importlib.import_module(f"protocols.{protocol_name}")
    cls = getattr(module, protocol_name)
    return cls(device, policy, env)


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

        # Get device info
        device = {
            "name": profile["device-info"]["device-name"],
            "mac":  profile["device-info"]["mac-address"],
            "ip":   profile["device-info"]["ip-address"]
        }

        # For testing only
        # Delete nftables table
        command = f"nft delete table netdev {device['name']}"

        # Create device directory
        Path(device["name"]).mkdir(exist_ok=True)

        # Header meta-information
        header_tpl = env.get_template("header.c.j2")
        header_dict = {"device": device["name"]}

        # Create device nftables table
        nft_table = f"netdev {device['name']}"
        command = f"nft add table {nft_table}"
        subprocess.run(command, shell=True)
    
        # Loop over the device's policies
        # Individual policies
        nfq_id_base = 0
        for policy in profile["individual-policies"]:
            value = profile["individual-policies"][policy]
            scenario = policy.replace("-", "_")
            direction = value.get("direction", "in")

            # Create nftables chain for policy
            nft_table_chain = f"{nft_table} {policy}"
            command = f"nft add chain {nft_table_chain} {{ type filter hook ingress device enp0s8 priority 0 \; policy drop \; }}"
            subprocess.run(command, shell=True)
            
            # Populate meta-information and constants
            header_dict["scenario"] = scenario
            header_dict["max_threads"] = 1
            header_dict["num_states"] = 2
            header_dict["nfq_id_base"] = nfq_id_base

            # Initialize accumulators for nftables rule and callback functions
            nft_rule = f"nft add rule {nft_table_chain} "
            nft_rule_backwards = f"nft add rule {nft_table_chain} " if direction == "both" else ""
            callback_funcs = ""

            for protocol_name in value["protocols"]:
                # Protocol decoding
                protocol = init_protocol(protocol_name, device, policy, env)
                if protocol.custom_parser:
                    header_dict["parsers"] = header_dict.get("parsers", "") + f"#include \"parsers/{protocol_name}.h\"\n"
                nft_rule, callback_funcs, nft_rule_backwards = protocol.parse(value["protocols"][protocol_name], nft_rule, callback_funcs, nft_rule_backwards)

            # End and apply nftables rule
            nft_rule += f"queue num {nfq_id_base}"
            subprocess.run(nft_rule, shell=True)
            if direction == "both":
                nft_rule_backwards += f"queue num {nfq_id_base}"
                subprocess.run(nft_rule_backwards, shell=True)
            nfq_id_base += 10

            # Render header
            header = header_tpl.render(header_dict)

            # Populate main function
            main_tpl = env.get_template("main.c.j2")
            main = main_tpl.render(scenario=scenario, nfq_id_offset=0)
            
            # Write full file
            with open(f"{device['name']}/{policy}.c", "w+") as fw:
                fw.write(header)
                fw.write(callback_funcs)
                fw.write(main)
