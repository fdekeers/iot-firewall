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


def construct_include(loader: IncludeLoader, node: yaml.Node):
    """
    Include member defined in another YAML file.
    """

    # Retrieve path of file and member to include
    scalar = loader.construct_scalar(node)
    split = scalar.split('#')
    filepath = os.path.join(os.path.abspath(os.path.dirname(loader.stream.name)), split[0])
    members = split[1].split('.')

    # Load member to include
    with open(filepath, 'r') as f:
        data = yaml.load(f, IncludeLoader)
        for member in members:
            data = data[member]
        return data


# Add custom constructor
yaml.add_constructor("!include", construct_include, IncludeLoader)
