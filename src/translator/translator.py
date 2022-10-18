import os
import argparse
from pathlib import Path
import yaml
import jinja2
import subprocess
from Policy import Policy
    

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

        # Initialize header Jinja2 template
        header_tpl = env.get_template("header.c.j2")
        header_dict = {"device": device["name"]}

        # Create device nftables table
        nft_table = f"netdev {device['name']}"
        command = f"nft add table {nft_table}"
        subprocess.run(command, shell=True)
    
        # Loop over the device's individual policies
        if "individual-policies" in profile:
            nfq_id_base = 0
            for policy_name in profile["individual-policies"]:
                # Populate Jinja2 templates with general data for single policies
                policy_jinja = policy_name.replace("-", "_")
                states = ["STATE_0", "STATE_1"]
                header_dict["policy"] = policy_jinja
                header_dict["max_threads"] = 1
                header_dict["states"] = states
                header_dict["nfq_id_base"] = nfq_id_base
                callback_dict = {"policy": policy_jinja, "multithread": False, "old_state": "STATE_0", "new_state": "STATE_1"}
                main_dict = {"policy": policy_jinja, "multithread": False, "nfq_id_offset": 0}

                # Create nftables chain for this policy
                command = f"nft add chain {nft_table} {policy_name} {{ type filter hook ingress device enp0s8 priority 0\; policy drop \; }}"
                subprocess.run(command, shell=True)

                # Create policy and parse it
                profile_data = profile["individual-policies"][policy_name]
                policy = Policy(policy_name, profile_data, device)
                accumulators = policy.parse()

                # Add nftables rules
                nft_rule_forward = f"nft add rule {nft_table} {policy_name}"
                nft_rule_backward = ""
                nft_matches = accumulators["nft"]
                for i in range(len(nft_matches)):
                    nft_rule_forward += f" {nft_matches[i]['forward']}"
                    # Add backward rule (if necessary)
                    if "backward" in nft_matches[i]:
                        nft_rule_backward = nft_rule_backward + f" {nft_matches[i]['backward']}" if nft_rule_backward else f"nft add rule {nft_table} {policy_name} {nft_matches[i]['backward']}"
                nft_rule_forward += f" queue num {nfq_id_base}"
                subprocess.run(nft_rule_forward, shell=True)
                if nft_rule_backward:
                    nft_rule_backward += f" queue num {nfq_id_base}"
                    subprocess.run(nft_rule_backward, shell=True)
                nfq_id_base += 10

                # Retrieve Jinja2 template directories
                header_dict = {**header_dict, **accumulators["jinja"]["header"]}
                callback_dict = {**callback_dict, **accumulators["jinja"]["callback"], "nfq": accumulators["nfq"]}
                main_dict = {**main_dict, **accumulators["jinja"]["main"]}

                # Render Jinja2 templates
                header = env.get_template("header.c.j2").render(header_dict)
                callback = env.get_template("callback.c.j2").render(callback_dict)
                main = env.get_template("main.c.j2").render(main_dict)

                # Write policy C file
                with open(f"{device['name']}/{policy_name}.c", "w+") as fw:
                    fw.write(header)
                    fw.write(callback)
                    fw.write(main)


    print("Done.")
