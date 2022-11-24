import os
import argparse
from pathlib import Path
import yaml
import jinja2
from Policy import Policy
import json


def flatten_policies(single_policy_name: str, single_policy: dict, acc: dict = {}) -> None:
    """
    Flatten a nested single policy into a list of single policies.

    Args:
        single_policy (dict): Single policy to be flattened
    Returns:
        list: List of single policies
    """
    if "protocols" in single_policy:
        acc[single_policy_name] = single_policy
    else:
        for subpolicy in single_policy:
            flatten_policies(subpolicy, single_policy[subpolicy], acc)


# Program entry point
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
        nft_counters = {}
        nfqueues = []
    
        # Loop over the device's individual policies
        if "individual-policies" in profile:
            for policy_name in profile["individual-policies"]:
                profile_data = profile["individual-policies"][policy_name]
                # Populate Jinja2 templates with general data for single policies
                states = ["STATE_0"]
                header_dict["policy"] = policy_name
                header_dict["nfq_id_base"] = nfq_id_base
                callback_dict = {
                    "nft_table": f"netdev {device['name']}",
                    "nft_chain": policy_name
                }

                # Create policy and parse it
                max_threads = 1
                policy = Policy(policy_name, profile_data, device)
                policy.parse()
                if policy.direction == "both":
                    max_threads += 1
                    states.append("STATE_1")

                # Add nftables rules
                nfq_id = nfq_id_base if (policy.direction == "both" or policy.nfq_matches or policy.counters) else -1
                nft_chains[policy_name] = [policy.build_nft_rule(nfq_id)]
                if policy.counters and "packet-count" in policy.counters:
                    nft_counters[policy_name] = policy.counters["packet-count"]

                # If need for user-space matching, create nfqueue C file
                if policy.direction == "both" or policy.nfq_matches or policy.counters:
                    # Retrieve Jinja2 template directories
                    custom_parsers = {policy_name: policy.custom_parser} if policy.custom_parser else {}
                    header_dict = {
                        **header_dict,
                        "max_threads": max_threads,
                        "states": states,
                        "custom_parsers": set(custom_parsers.values())
                    }
                    callback_dict = {
                        **callback_dict,
                        "multithread": max_threads > 1,
                        "states": states,
                        "policies": [policy]
                    }
                    main_dict = {
                        "multithread": max_threads > 1,
                        "policies": [policy]
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
                    nfq_id_base += 100


        # Loop over the device's interaction policies
        if "interaction-policies" in profile:
            for interaction_policy_name in profile["interaction-policies"]:
                interaction_policy = profile["interaction-policies"][interaction_policy_name]
                # Populate Jinja2 templates with general data for interaction policies
                header_dict["policy"] = interaction_policy_name
                states = ["STATE_0"]
                header_dict["nfq_id_base"] = nfq_id_base
                callback_dict = {
                    "nfq_id_base": nfq_id_base,
                    "nft_table": f"netdev {device['name']}",
                    "nft_chain": interaction_policy_name
                }

                # Iterate on single policies
                i = 0
                nfq_id_offset = 0
                current_state = 0
                max_threads = 0
                custom_parsers = {}
                policies = []
                nft_chains[interaction_policy_name] = []
                single_policies = {}

                # First pass, to flatten nested policies
                for single_policy_name in interaction_policy:
                    flatten_policies(single_policy_name, interaction_policy[single_policy_name], single_policies)

                # Second pass, parse policies
                for single_policy_name in single_policies:
                    # Create policy and parse it
                    profile_data = single_policies[single_policy_name]
                    single_policy = Policy(single_policy_name, profile_data, device)
                    single_policy.parse()
                    policies.append(single_policy)

                    # Add states for this policy (if needed)
                    if not single_policy.periodic:
                        if (i < len(single_policies) - 1) or (single_policy.direction == "both" and not single_policy.transient):
                            current_state += 1
                            states.append(f"STATE_{current_state}")
                        if (i < len(single_policies) - 1) and (single_policy.direction == "both" and not single_policy.transient):
                            current_state += 1
                            states.append(f"STATE_{current_state}")

                    # Add threads for this policy
                    if not single_policy.periodic or single_policy.nfq_matches or single_policy.counters:
                        max_threads += 1
                        if single_policy.direction == "both":
                            max_threads += 1

                    # Add custom parser (if any)
                    if single_policy.custom_parser:
                        custom_parsers[single_policy_name] = single_policy.custom_parser

                    # Add nftables counter (if any)
                    if single_policy.counters and "packet-count" in single_policy.counters:
                        nft_counters[single_policy_name] = single_policy.counters["packet-count"]

                    # Add nftables rules
                    if not single_policy.periodic:
                        nft_chains[interaction_policy_name].append(single_policy.build_nft_rule(nfq_id_base + nfq_id_offset))
                        nfq_id_offset += 1
                        if single_policy.direction == "both":
                            nfq_id_offset += 1
                    
                    i += 1
                
                # Render Jinja2 templates
                header_dict = {
                    **header_dict,
                    "max_threads": max_threads,
                    "custom_parsers": set(custom_parsers.values()),
                    "states": states
                }
                header = env.get_template("header.c.j2").render(header_dict)
                callback_dict = {
                    **callback_dict,
                    "multithread": max_threads > 1,
                    "states": states,
                    "policies": policies
                }
                callback = env.get_template("callback.c.j2").render(callback_dict)
                main_dict = {
                    "multithread": max_threads > 1,
                    "policies": policies
                }
                main = env.get_template("main.c.j2").render(main_dict)

                # Write policy C file
                with open(f"{nfqueues_path}/{interaction_policy_name}.c", "w+") as fw:
                    fw.write(header)
                    fw.write(callback)
                    fw.write(main)
            
                nfqueues.append(interaction_policy_name)
                nfq_id_base += 100

        # Create nftables script
        nft_dict = {
            "device": device["name"],
            "nft_chains": nft_chains,
            "counters": nft_counters
        }
        env.get_template("firewall.nft.j2").stream(nft_dict).dump(f"{device_path}/firewall.nft")

        # Create CMake file
        cmake_dict = {
            "device": device["name"],
            "nfqueues": nfqueues
        }
        env.get_template("CMakeLists.txt.j2").stream(cmake_dict).dump(f"{device_path}/CMakeLists.txt")

    print("Done.")
