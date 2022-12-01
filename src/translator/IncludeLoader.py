"""
PyYAML loader which supports inclusion of external members.
Adapted from https://gist.github.com/joshbode/569627ced3076931b02f.
"""

import os
import yaml


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
        node: YAML node, i.e. the value occurring after the key "!include"
    Returns:
        dict: included pattern (from this or another YAML profile)
    """

    # Retrieve path of file and member to include
    scalar = loader.construct_scalar(node)
    split = scalar.split('#')
    path = os.path.abspath(loader.stream.name)  # Default path, the current profile
    if len(split) == 1:
        members = split[0]
    elif len(split) == 2:
        if split[0] != "self":
            path = os.path.join(os.path.dirname(path), split[0])
        members = split[1]

    # Load member to include
    with open(path, 'r') as f:
        data = yaml.load(f, IncludeLoader)
        for member in members.split('.'):
            data = data[member]
        return data


# Add custom constructor
yaml.add_constructor("!include", construct_include, IncludeLoader)
