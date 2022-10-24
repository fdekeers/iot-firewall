import os
import argparse
from pathlib import Path
import yaml
import jinja2
from Policy import Policy
    

if __name__ == "__main__":

    # Get script path
    script_path = os.path.abspath(os.path.dirname(__file__))

    # Commande line arguments
    description = "Translate a device YAML profile to a corresponding nfqueue C code"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("profile", help="Path to the device YAML profile")
    args = parser.parse_args()

    # Jinja loader
    loader = jinja2.FileSystemLoader(searchpath=f"{script_path}/templates")
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

        # Create device directory
        device_path = f"{script_path}/../../devices/{device['name']}"
        nfqueues_path = f"{device_path}/nfqueues"
        Path(nfqueues_path).mkdir(parents=True, exist_ok=True)

        # Initialize header Jinja2 template
        header_tpl = env.get_template("header.c.j2")
        header_dict = {"device": device["name"]}

        nfq_id_base = 0  # Base nfqueue id, will be incremented by 10 for each high-level policy
        nft_chains = {}
        nfqueues = []
    
        # Loop over the device's individual policies
        if "individual-policies" in profile:
            for policy_name in profile["individual-policies"]:
                profile_data = profile["individual-policies"][policy_name]
                # Populate Jinja2 templates with general data for single policies
                states = ["STATE_0", "STATE_1"]
                header_dict["policy"] = policy_name
                header_dict["max_threads"] = 1
                header_dict["states"] = states
                header_dict["nfq_id_base"] = nfq_id_base
                direction = profile_data["direction"]
                callback_dict = {
                    "policy": policy_name,
                    "multithread": False,
                    "states": states,
                    "current_state": 0,
                    "direction": direction
                }
                main_dict = {
                    "policy": policy_name,
                    "multithread": False,
                    "nfq_id_offset": 0
                }

                # Create policy and parse it
                policy = Policy(policy_name, profile_data, device)
                accumulators = policy.parse()

                # Add nftables rules
                nft_rule_forward = ""
                nft_rule_backward = ""
                nft_matches = accumulators["nft"]
                for i in range(len(nft_matches)):
                    if i > 0:
                        nft_rule_forward += " "
                    nft_rule_forward += f"{nft_matches[i]['forward']}"
                    # Add backward rule (if necessary)
                    if direction == "both" and "backward" in nft_matches[i]:
                        if i > 0:
                            nft_rule_backward += " "
                        nft_rule_backward += f"{nft_matches[i]['backward']}"
                suffix = f" queue num {nfq_id_base}" if accumulators["nfq"] else " accept"
                nft_rule_forward += suffix
                rule = {"forward": nft_rule_forward}
                if direction == "both" and nft_rule_backward:
                    nft_rule_backward += suffix
                    rule["backward"] = nft_rule_backward
                nft_chains[policy_name] = [rule]

                # If need for user-space matching, create nfqueue C file
                if accumulators["nfq"]:
                    # Retrieve Jinja2 template directories
                    custom_parsers = {policy_name: accumulators["custom_parser"]} if "custom_parser" in accumulators else {}
                    header_dict = {
                        **header_dict,
                        "custom_parsers": set(custom_parsers.values())
                    }
                    callback_dict = {
                        **callback_dict,
                        "custom_parsers": custom_parsers,
                        "nfq": accumulators["nfq"]
                    }

                    # Render Jinja2 templates
                    header = env.get_template("header.c.j2").render(header_dict)
                    callback = env.get_template("callback.c.j2").render(callback_dict)
                    main = env.get_template("main.c.j2").render(main_dict)

                    # Write policy C file
                    with open(f"{nfqueues_path}/{policy_name}.c", "w+") as fw:
                        fw.write(header)
                        fw.write(callback)
                        fw.write(main)
                    
                    nfqueues.append(policy_name)
                    nfq_id_base += 10


        # Loop over the device's interaction policies
        if "interaction-policies" in profile:
            for interaction_policy_name in profile["interaction-policies"]:
                interaction_policy = profile["interaction-policies"][interaction_policy_name]
                # Populate Jinja2 templates with general data for interaction policies
                header_dict["policy"] = policy_name
                header_dict["max_threads"] = len(interaction_policy)
                multithread = len(interaction_policy) > 1
                states = list(map(lambda i: f"STATE_{i}", range(len(interaction_policy))))
                header_dict["states"] = states
                header_dict["nfq_id_base"] = nfq_id_base
                callback_dict = {"multithread": multithread}
                main_dict = {"policy": policy_name, "multithread": multithread}

                # Iterate on single policies
                current_state = 0
                custom_parsers = {}
                policies = []
                nft_chains[interaction_policy_name] = []
                callback_funcs = ""
                for single_policy_name in interaction_policy:
                    # Create policy and parse it
                    policies.append(single_policy_name)
                    profile_data = interaction_policy[single_policy_name]
                    direction = profile_data["direction"]
                    single_policy = Policy(single_policy_name, profile_data, device)
                    accumulators = single_policy.parse()

                    # Update high-level accumulators
                    if "custom_parser" in accumulators:
                        custom_parsers[single_policy_name] = accumulators["custom_parser"]

                    # Add nftables rules
                    nft_rule_forward = ""
                    nft_rule_backward = ""
                    nft_matches = accumulators["nft"]
                    for i in range(len(nft_matches)):
                        if i > 0:
                            nft_rule_forward += " "
                        nft_rule_forward += f"{nft_matches[i]['forward']}"
                        # Add backward rule (if necessary)
                        if direction == "both" and "backward" in nft_matches[i]:
                            if i > 0:
                                nft_rule_backward += " "
                            nft_rule_backward += f"{nft_matches[i]['backward']}"
                    suffix = f" queue num {nfq_id_base + current_state}"
                    nft_rule_forward += suffix
                    rule = {"forward": nft_rule_forward}
                    if direction == "both" and nft_rule_backward:
                        nft_rule_backward += suffix
                        rule["backward"] = nft_rule_backward
                    nft_chains[interaction_policy_name].append(rule)

                    # Add callback function for this single policy
                    callback_dict = {
                        **callback_dict,
                        "policy": single_policy_name,
                        "custom_parsers": custom_parsers,
                        "states": states,
                        "current_state": current_state,
                        "direction": direction,
                        "nfq": accumulators["nfq"]}
                    callback_funcs += env.get_template("callback.c.j2").render(callback_dict)

                    current_state += 1
                
                # Render Jinja2 templates
                header_dict = {
                    **header_dict,
                    "custom_parsers": set(custom_parsers.values())
                }
                header = env.get_template("header.c.j2").render(header_dict)
                main_dict = {**main_dict, "policies": policies}
                main = env.get_template("main.c.j2").render(main_dict)

                # Write policy C file
                with open(f"{nfqueues_path}/{interaction_policy_name}.c", "w+") as fw:
                    fw.write(header)
                    fw.write(callback_funcs)
                    fw.write(main)
            
                nfqueues.append(interaction_policy_name)
                nfq_id_base += 10

        # Create nftables script
        nft_dict = {
            "device": device["name"],
            "nft_chains": nft_chains
        }
        env.get_template("firewall.nft.j2").stream(nft_dict).dump(f"{device_path}/firewall.nft")

        # Create CMake file
        cmake_dict = {
            "device": device["name"],
            "nfqueues": nfqueues
        }
        env.get_template("CMakeLists.txt.j2").stream(cmake_dict).dump(f"{device_path}/CMakeLists.txt")

    print("Done.")
