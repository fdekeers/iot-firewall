import os
import argparse
from pathlib import Path
import yaml
import jinja2
from Policy import Policy
from yaml_loaders.IncludeLoader import IncludeLoader


def is_list(value: any) -> bool:
    """
    Custom filter for Jinja2, to check whether a value is a list.

    Args:
        value (any): Value to check
    Returns:
        bool: True if value is a list, False otherwise
    """
    return type(value) == list


def debug(value: any) -> str:
    """
    Custom filter for Jinja2, to print a value.

    Args:
        value (any): Value to print
    Returns:
        str: An empty string
    """
    print(str(value))
    return ""


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
        if "backward" in single_policy and single_policy["backward"]:
            acc[f"{single_policy_name}-backward"] = single_policy
    else:
        for subpolicy in single_policy:
            flatten_policies(subpolicy, single_policy[subpolicy], acc)


def parse_policy(policy_data: dict, acc: dict, policies_count: int, parent_policy: str = None) -> Policy:
    """
    Parse a policy.

    Args:
        policy_data (dict): Dictionary containing all the necessary data to create a Policy object
        acc (dict): Dictionary containing the local accumulators that must be updated when parsing this policy
        policies_count (int): Number of policies in the interaction
        parent_policy (str): Optional, name of the parent policy.
                             If `None`, the name of the policy itself will be used as the parent policy name.
    Returns:
        Policy: the parsed policy, as a `Policy` object
    """
    # Create and parse policy
    policy = Policy(**policy_data)
    policy.parse()
    # Build policy nftables rule
    nfq_id = acc["nfq_id"] if ((policy_data["is_backward"] and not policy.periodic) or policy.nfq_matches or policy.counters) else -1
    nft_rule = policy.build_nft_rule(nfq_id)

    # Derive policy names
    policy_name = policy_data["policy_name"]
    full_policy_name = ""
    if policy_data["is_backward"]:
        policy_backward_name = policy_data["policy_name"]
        default_policy_name = policy_backward_name[:-len("-backward")]
    else:
        # Policy direction is forward
        default_policy_name = policy_name
    if parent_policy is None:
        parent_policy = default_policy_name
        full_policy_name = parent_policy
    else:
        full_policy_name = f"{parent_policy}-{default_policy_name}"

    # Add threads for this policy
    if policy.nfq_matches or policy.counters or (policies_count > 1 and not policy.periodic):
        acc["max_threads"] += 1

    # Add states for this policy (if needed)
    last_policy = acc["index"] == policies_count - 1
    add_state = not last_policy and not policy.periodic and (not policy.transient or not policy.is_backward)
    if add_state:
        acc["current_state"] += 1
        acc["states"].append(f"STATE_{acc['current_state']}")

    # Add counters (if any)
    for counter_name in Policy.counters:
        if counter_name in policy.counters:
            counter = policy.counters[counter_name]
            acc["max_counters"][counter_name] = acc["max_counters"].get(counter_name, 0) + len(counter)
    
    # Add custom parser (if any)
    if policy.custom_parser:
        acc["custom_parsers"].add(policy.custom_parser)

    # Add nftables rules
    acc["top_policies"][parent_policy] = acc["top_policies"].get(parent_policy, []) + [policy]
    acc["map_rule_to_policies"][policy.nft_match] = acc["map_rule_to_policies"].get(policy.nft_match, []) + [policy]

    # Add nftables counters (if any)
    if policy.counters and "packet-count" in policy.counters:
        acc["map_policy_to_counters"][full_policy_name] = acc["map_policy_to_counters"].get(full_policy_name, []) + [policy.counters["packet-count"]]

    acc["index"] += 1
    acc["nfq_id"] += 1
    return policy


# Program entry point
if __name__ == "__main__":

    # Commande line arguments
    description = "Translate a device YAML profile to a corresponding nfqueue C code"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("profile", help="Path to the device YAML profile")
    args = parser.parse_args()

    # Retrieve useful paths
    script_path = os.path.abspath(os.path.dirname(__file__))      # This script's path
    device_path = os.path.abspath(os.path.dirname(args.profile))  # Device profile's path

    # Jinja2 loader
    loader = jinja2.FileSystemLoader(searchpath=f"{script_path}/templates")
    env = jinja2.Environment(loader=loader, trim_blocks=True, lstrip_blocks=True)
    # Add custom Jinja2 filters
    env.filters["is_list"] = is_list
    env.filters["debug"] = debug

    # Load the device profile
    with open(args.profile, "r") as f:
        
        # Load YAML profile with custom loader
        profile = yaml.load(f, IncludeLoader)

        # Get device info
        device = profile["device-info"]

        # Create device directory
        nfqueues_path = f"{device_path}/nfqueues"
        Path(nfqueues_path).mkdir(parents=True, exist_ok=True)

        # Initialize header Jinja2 template
        header_tpl = env.get_template("header.c.j2")
        header_dict = {"device": device["name"]}

        nfq_id_base = 0  # Base nfqueue id, will be incremented by 100 for each high-level policy
        # Accumulators
        acc = {
            "top_policies": {},
            "map_rule_to_policies": {},
            "map_policy_to_counters": {},
        }
        nfqueues = []
    
        # Loop over the device's individual policies
        if "individual-policies" in profile:
            for policy_name in profile["individual-policies"]:
                profile_data = profile["individual-policies"][policy_name]
                # Populate Jinja2 templates with general data for single policies
                header_dict["policy"] = policy_name
                header_dict["nfq_id_base"] = nfq_id_base
                callback_dict = {
                    "nft_table": f"netdev {device['name']}",
                    "top_policy": policy_name
                }

                policies = []
                policy_data = {
                    "policy_name": policy_name,
                    "profile_data": profile_data,
                    "device": device,
                    "is_backward": False
                }
                acc = {
                    **acc,
                    "index": 0,
                    "current_state": 0,
                    "states": ["STATE_0"],
                    "max_threads": 0,
                    "max_counters": {},
                    "custom_parsers": set(),
                    "nfq_id": nfq_id_base
                }
                
                # Parse policy
                is_backward = "backward" in profile_data and profile_data["backward"]
                policies_count = 2 if is_backward else 1
                policy = parse_policy(policy_data, acc, policies_count)
                policies.append(policy)
                # Parse policy in backward direction, if needed
                if is_backward:
                    policy_data_backward = {
                        "policy_name": f"{policy_name}-backward",
                        "profile_data": profile_data,
                        "device": device,
                        "is_backward": True
                    }
                    policy_backward = parse_policy(policy_data_backward, acc, policies_count)
                    policies.append(policy_backward)

                # If need for user-space matching, create nfqueue C file
                if (is_backward and not policy.periodic) or policy.nfq_matches or policy.counters:
                    # Retrieve Jinja2 template directories
                    header_dict = {
                        **header_dict,
                        "max_threads": acc["max_threads"],
                        "max_counters": acc["max_counters"],
                        "states": acc["states"],
                        "custom_parsers": acc["custom_parsers"]
                    }
                    callback_dict = {
                        **callback_dict,
                        "multithread": acc["max_threads"] > 1,
                        "states": acc["states"],
                        "policies": policies
                    }
                    main_dict = {
                        "multithread": acc["max_threads"] > 1,
                        "max_counters": acc["max_counters"],
                        "policies": policies,
                        "custom_parsers": acc["custom_parsers"]
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
                header_dict["nfq_id_base"] = nfq_id_base
                callback_dict = {
                    "nft_table": f"netdev {device['name']}",
                    "top_policy": interaction_policy_name
                }

                # Iterate on single policies

                # First pass, to flatten nested policies
                single_policies = {}
                for single_policy_name in interaction_policy:
                    flatten_policies(single_policy_name, interaction_policy[single_policy_name], single_policies)

                # Second pass, parse policies
                policies = []
                acc = {
                    **acc,
                    "index": 0,
                    "current_state": 0,
                    "states": ["STATE_0"],
                    "max_threads": 0,
                    "max_counters": {},
                    "custom_parsers": set(),
                    "nfq_id": nfq_id_base
                }

                for single_policy_name in single_policies:
                    # Create policy and parse it
                    profile_data = single_policies[single_policy_name]
                    is_backward = "backward" in single_policy_name and "backward" in profile_data and profile_data["backward"]
                    policy_data = {
                        "policy_name": single_policy_name,
                        "profile_data": profile_data,
                        "device": device,
                        "is_backward": is_backward
                    }
                    single_policy = parse_policy(policy_data, acc, len(single_policies), interaction_policy_name)
                    policies.append(single_policy)
                
                # Render Jinja2 templates
                header_dict = {
                    **header_dict,
                    "max_threads": acc["max_threads"],
                    "max_counters": acc["max_counters"],
                    "custom_parsers": acc["custom_parsers"],
                    "states": acc["states"]
                }
                header = env.get_template("header.c.j2").render(header_dict)
                callback_dict = {
                    **callback_dict,
                    "multithread": acc["max_threads"] > 1,
                    "states": acc["states"],
                    "policies": policies
                }
                callback = env.get_template("callback.c.j2").render(callback_dict)
                main_dict = {
                    "multithread": acc["max_threads"] > 1,
                    "max_counters": acc["max_counters"],
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
            "nft_policies": acc["top_policies"],
            "counters": acc["map_policy_to_counters"]
        }
        env.get_template("firewall.nft.j2").stream(nft_dict).dump(f"{device_path}/firewall.nft")

        # Create CMake file
        cmake_dict = {
            "device": device["name"],
            "nfqueues": nfqueues
        }
        env.get_template("CMakeLists.txt.j2").stream(cmake_dict).dump(f"{device_path}/CMakeLists.txt")

    print(f"Done translating {args.profile}.")
