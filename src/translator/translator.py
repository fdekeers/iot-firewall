import os
import argparse
from pathlib import Path
import yaml
import jinja2
import subprocess
from protocols.Protocol import Protocol


if __name__ == "__main__":

    # Get script path
    path = os.path.abspath(os.path.dirname(__file__))

    # Commande line arguments
    description = "Translate a device YAML profile to a corresponding nfqueue C code"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("profile", help="Path to the device YAML profile")
    args = parser.parse_args()

    # Jinja loader
    loader = jinja2.FileSystemLoader(searchpath=f"{path}/templates")
    env = jinja2.Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)

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
        try:
            output = subprocess.check_output(command, shell=True)
        except subprocess.CalledProcessError as e:
            pass

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
            header_dict["states"] = ["STATE_0", "STATE_1"]

            # Initialize accumulators for nftables rule and callback functions
            states = {"old": "STATE_0", "new": "STATE_1"}
            accumulators = {"nft_rule": f"nft add rule {nft_table_chain} ", "callback_funcs": ""}
            if direction == "both":
                accumulators["nft_rule_backwards"] = f"nft add rule {nft_table_chain} "

            for protocol_name in value["protocols"]:
                # Protocol decoding
                metadata = {"protocol": protocol_name, "device": device, "policy": policy}
                parsing_data = {"profile_data": value["protocols"][protocol_name], "states": states, "accumulators": accumulators}
                protocol = Protocol.init_protocol(metadata, parsing_data, env)
                if protocol.custom_parser:
                    # Protocol uses a custom parser, include its header in the C file
                    header_dict["parsers"] = header_dict.get("parsers", "") + f"#include \"parsers/{protocol_name}.h\"\n"
                protocol.parse()

            # End and apply nftables rule
            accumulators["nft_rule"] += f" queue num {nfq_id_base}"
            subprocess.run(accumulators["nft_rule"], shell=True)
            if direction == "both":
                accumulators["nft_rule_backwards"] += f" queue num {nfq_id_base}"
                subprocess.run(accumulators["nft_rule_backwards"], shell=True)
            nfq_id_base += 10

            # Render header
            header = header_tpl.render(header_dict)

            # Populate main function
            main_tpl = env.get_template("main.c.j2")
            main = main_tpl.render(scenario=scenario, nfq_id_offset=0)
            
            # Write full file
            with open(f"{device['name']}/{policy}.c", "w+") as fw:
                fw.write(header)
                fw.write(accumulators["callback_funcs"])
                fw.write(main)


        # Interaction policies
        #for policy in profile["interaction-policies"]:


    print("Done.")
