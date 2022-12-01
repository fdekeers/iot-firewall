"""
PyYAML loader which supports inclusion of external members.
Adapted from https://gist.github.com/joshbode/569627ced3076931b02f.
"""

import sys
import os
import yaml

# Import IgnoreLoader
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from IgnoreLoader import IgnoreLoader


class IncludeLoader(yaml.SafeLoader):
    """
    Custom PyYAML loader, which supports inclusion of members defined in other YAML files.
    """
    def __init__(self, stream) -> None:
        # Use parent constructor
        super().__init__(stream)


def construct_include(loader: IncludeLoader, node: yaml.Node) -> dict:
    """
    Include member defined in another YAML file.

    Args:
        loader: PyYAML IncludeLoader
        node: YAML node, i.e. the value occurring after the tag
    Returns:
        dict: included pattern (from this or another YAML profile)
    """
    scalar = loader.construct_scalar(node)
    
    # Split profile and values
    split1 = scalar.split(" ")
    profile = split1[0]
    values = split1[1:]

    # Parse values into dictionary
    values_dict = {}
    for value in values:
        split_value = value.split(":")
        if len(split_value) == 2:
            values_dict[split_value[0]] = split_value[1]

    # Split path and pattern from profile
    split2 = profile.split('#')
    path = os.path.abspath(loader.stream.name)  # Default path, the current profile
    if len(split2) == 1:
        members = split2[0]
    elif len(split2) == 2:
        if split2[0] != "self":
            path = os.path.join(os.path.dirname(path), split2[0])
        members = split2[1]

    # Load member to include
    data = {}
    with open(path, 'r') as f:
        data = yaml.load(f, IgnoreLoader)
        for member in members.split('.'):
            data = data[member]
    
    # Populate values
    data_top = data
    for key, value in values_dict.items():
        split_key = key.split('.')
        i = 0
        for sub_key in split_key:
            if i == len(split_key) - 1:
                data[sub_key] = value
            else:
                data = data[sub_key]
                i += 1
    
    return data_top


# Add custom constructor
yaml.add_constructor("!include", construct_include, IncludeLoader)
